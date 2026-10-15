#include <iostream>      // For std::cout, std::cerr (console I/O)
#include <thread>        // For std::thread (multithreading)
#include <cstring>       // For memset, strcmp (C-style string operations)
#include <netinet/in.h>  // For sockaddr_in (network structures)
#include <sstream>       // For std::stringstream (string manipulation)
#include <openssl/pem.h> // For PEM_read_PrivateKey (reading PEM keys)
#include <openssl/err.h> // For ERR_print_errors_fp, ERR_error_string (OpenSSL error handling)
#include <fstream>       // For std::ifstream, std::ofstream (file I/O)
#include <iomanip>       // For std::setw, std::setfill, std::hex (hex formatting in toHex)

#include "utility.h"

// ----- FILE PATHS -----
#define SERVER_PRIV_KEY_FILE "keys/server_priv.pem" // Server private key file
#define DSS_MASTER_KEY_FILE "keys/dss_master.key"  // DSS master key file
#define EMPLOYEES_DB_FILE "data/employees.csv"      // Employee database file

// declarations
// function for sending encrypted and authenticated messages
bool sendToClientSecure(int sock, const byte_vec &cmd, const byte_vec &argument,
                        byte_vec &s_nonce, byte_vec &c_nonce,
                        const byte_vec &s_key, const byte_vec &s_mac, 
                        std::set<byte_vec> &used_server_nonces);

// function that converts std::string -> byte_vec
std::string toHex(const byte_vec &data);

// function that loads the DSS master key from a file
byte_vec loadDssMasterKey(const char *filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        std::cerr << "ERROR: Cannot open DSS master key file: " << filename << std::endl;
        return {};
    }

    byte_vec key(AES_KEY_SIZE);
    if (!file.read(reinterpret_cast<char *>(key.data()), key.size()))
    {
        std::cerr << "ERROR: Failed to read DSS master key" << std::endl;
        return {};
    }

    return key;
}

// function that loads the public key of a specified user
EVP_PKEY *loadUserPublicKey(const std::string &username)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    std::string line;
    std::getline(infile, line); // header

    while (std::getline(infile, line))
    {
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        if (cols.size() < CSV_COLUMNS)
            continue;
        if (cols[0] == username && !cols[6].empty())
        {
            byte_vec pub_der = fromHex(cols[6]);
            const unsigned char *p = pub_der.data();
            return d2i_PUBKEY(nullptr, &p, pub_der.size());
        }
    }
    return nullptr;
}

// function that loads the private key of a specified user
EVP_PKEY *loadUserPrivateKey(const std::string &username,
                             const byte_vec &DSS_MASTER_KEY)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    std::string line;
    std::getline(infile, line);

    while (std::getline(infile, line))
    {
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        if (cols.size() < CSV_COLUMNS)
            continue;
        if (cols[0] == username && !cols[5].empty())
        {

            auto sep = cols[5].find(':');
            byte_vec iv = fromHex(cols[5].substr(0, sep));
            byte_vec enc = fromHex(cols[5].substr(sep + 1));

            byte_vec priv_der;
            if (!cbcDecrypt(enc, DSS_MASTER_KEY, iv, priv_der))
                return nullptr;

            const unsigned char *p = priv_der.data();
            return d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &p, priv_der.size());
        }
    }
    return nullptr;
}

// username validation: max 50 char, only alphanumeric and underscore
bool isValidUsername(const std::string &username)
{
    if (username.empty() || username.length() > 50)
        return false;

    for (char c : username)
    {
        if (!std::isalnum(c) && c != '_')
            return false;
    }
    return true;
}

// password validation: max 128 char, no commas or newlines
bool isValidPassword(const std::string &password)
{
    if (password.empty() || password.length() > 128)
        return false;

    for (char c : password)
    {
        if (c == ',' || c == '\n' || c == '\r')
            return false;
    }
    return true;
}

// function to change the password of an user
bool changeUserPassword(const std::string &username, const std::string &new_password);

// function that loads the server private key from a file PEM
EVP_PKEY *loadServerPrivKey(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        std::cerr << "ERROR: Cannot open server private key file: " << filename << std::endl;
        return nullptr;
    }

    EVP_PKEY *s_pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!s_pkey)
    {
        std::cerr << "ERROR: Failed to read server private key from " << filename << std::endl;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    return s_pkey;
}

// Function that sends server nonce, client nonce (echo), DH public key, 
// IV, encrypted signature (of c_nonce||s_nonce||c_dh_pubkey||s_dh_pubkey), and HMAC to the client.
// The signature is encrypted with s_key for key confirmation.
// HMAC authenticates: [s_nonce][c_nonce][s_dh_pubkey][IV][enc_signature] using s_mac.
// Message format: [len][s_nonce][len][c_nonce][len][s_dh_pubkey][len][IV][len][enc_signature][len][HMAC]
bool sendServerKeys(int sock, EVP_PKEY *s_sign_key, const byte_vec &s_nonce, const byte_vec &c_nonce,
                    const byte_vec &c_dh_pubkey_bin, const byte_vec &s_dh_pubkey_bin,
                    const byte_vec &s_key, const byte_vec &s_mac)
{
    byte_vec totalMsg;

    // Create the digital signature
    byte_vec to_sign;
    push_field(to_sign, c_nonce);         // Prevents client nonce manipulation
    push_field(to_sign, s_nonce);         // Prevents server nonce manipulation
    push_field(to_sign, c_dh_pubkey_bin); // DH client public key
    push_field(to_sign, s_dh_pubkey_bin); // DH server public key

    // Compute the digital signature using RSA and SHA-256
    byte_vec signature(RSA_SIGNATURE_SIZE);
    size_t siglen = signature.size();
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;
    if (EVP_DigestSignInit(mdctx, nullptr, HASH_ALGORITHM, nullptr, s_sign_key) <= 0 ||
        EVP_DigestSignUpdate(mdctx, to_sign.data(), to_sign.size()) <= 0 ||
        EVP_DigestSignFinal(mdctx, nullptr, &siglen) <= 0)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    signature.resize(siglen);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &siglen) <= 0)
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    EVP_MD_CTX_free(mdctx);

    // key confirmation: encrypt the signature with s_key
    byte_vec iv(IV_SIZE);
    if(!RAND_bytes(iv.data(), iv.size())){
        std::cerr << "ERROR: Failed to generate IV for signature encryption" << std::endl;
        return false;
    }
    byte_vec enc_signature;
    if (!cbcEncrypt(signature, s_key, iv, enc_signature))
        return false;

    // HMAC on [s_nonce || c_nonce || s_dh_pubkey_bin || iv || enc_signature] with s_mac
    byte_vec to_auth;
    push_field(to_auth, s_nonce);
    push_field(to_auth, c_nonce);
    push_field(to_auth, s_dh_pubkey_bin);
    push_field(to_auth, iv);
    push_field(to_auth, enc_signature);

    byte_vec hmac;
    if (!computeHMAC(s_mac, to_auth, hmac))
        return false;

    // Append all fields to totalMsg
    push_field(totalMsg, s_nonce);
    push_field(totalMsg, c_nonce);
    push_field(totalMsg, s_dh_pubkey_bin);
    push_field(totalMsg, iv);
    push_field(totalMsg, enc_signature);
    push_field(totalMsg, hmac);

    // Send the whole message
    if (send_msg(sock, reinterpret_cast<const char *>(totalMsg.data()), totalMsg.size()) != (ssize_t)totalMsg.size())
    {
        std::cerr << "send_msg error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return false;
    }

    return true;
}

// only declaration
// function for receiving encrypted and authenticated messages
bool recvFromClientSecure(int sock, byte_vec &cmd, byte_vec &argument,
                          byte_vec &s_nonce, byte_vec &c_nonce,
                          const byte_vec &c_key, const byte_vec &c_mac,
                          std::set<byte_vec> &used_client_nonces);

// function that includes all the operations for the handshake
// for the creation of the secure channel server side
bool handshakeSecureChannelServer(int sock, EVP_PKEY *s_priv_key, byte_vec &c_nonce, byte_vec &s_nonce, byte_vec &c_key, byte_vec &c_mac, byte_vec &s_key, byte_vec &s_mac, std::set<byte_vec> &used_client_nonces, std::set<byte_vec> &used_server_nonces)
{
    // receiving the client DH public key
    // DEBUG
    // std::cout << "Receiving client DH public key..." << std::endl;
    //
    byte_vec buffer(BUFFER_SIZE); // dimensione massima
    ssize_t n = recv_msg(sock, reinterpret_cast<char *>(buffer.data()), buffer.size());
    if (n <= 0)
    {
        std::cerr << "recv_msg error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return false;
    }
    buffer.resize(n);

    size_t offset = 0;
    byte_vec c_dh_pubkey_bin;
    if (!extract_field(c_nonce, buffer, offset) ||
        !extract_field(c_dh_pubkey_bin, buffer, offset))
    {
        std::cerr << "ERROR: Malformed handshake message" << std::endl;
        return false;
    }
    // INFO
    std::cout << "INFO - New client DH public key received." << std::endl
              << std::endl;

    // convertion client DH public key to EVP_PKEY
    const unsigned char *p = c_dh_pubkey_bin.data();
    EVP_PKEY *peer_dh_pubkey = d2i_PUBKEY(NULL, &p, c_dh_pubkey_bin.size());
    if (!peer_dh_pubkey)
    {
        std::cerr << "d2i_PUBKEY error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return false;
    }

    // generation of server DH keypair
    // DEBUG
    // std::cout << "Generation of server DH key pair..." << std::endl;
    //
    EVP_PKEY *dh_keypair = nullptr;
    if (!generate_dh_keys(&dh_keypair))
    {
        std::cerr << "generate_dh_keys error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_free(dh_keypair);
        return false;
    }
    // INFO
    std::cout << "INFO - Server DH key pair successfully generated." << std::endl
              << std::endl;

    // extraction of the server DH public key from the keypair
    byte_vec s_dh_pubkey_bin;
    if (!extract_dh_public_key_der(dh_keypair, s_dh_pubkey_bin))
    {
        std::cerr << "extract_dh_public_key_der error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_free(peer_dh_pubkey);
        EVP_PKEY_free(dh_keypair);
        return false;
    }

    // generation of the shared key
    // DEBUG
    // std::cout << "Generation of DH shared key..." << std::endl;
    //
    byte_vec DH_shared_key;
    if (!generate_dh_shared_key(dh_keypair, c_dh_pubkey_bin, DH_shared_key))
    {
        std::cerr << "generate_dh_shared_key error: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        EVP_PKEY_free(dh_keypair);
        EVP_PKEY_free(peer_dh_pubkey);
        return false;
    }
    // INFO
    std::cout << "INFO - DH shared key successfully generated." << std::endl
              << std::endl;

    // create the nonce
    // DEBUG
    // std::cout << "Generating nonce..." << std::endl;
    //
    s_nonce.resize(NONCE_SIZE);
    int max_attempts = 500;
    int attempts = 0;

    do
    {
        if (RAND_bytes(s_nonce.data(), s_nonce.size()) != 1)
        {
            std::cerr << "ERROR: Failed to generate server nonce" << std::endl;
            EVP_PKEY_free(dh_keypair);
            EVP_PKEY_free(peer_dh_pubkey);
            return false;
        }
        attempts++;
        if (attempts >= max_attempts)
        {
            std::cerr << "ERROR: Failed to generate unique nonce after " << max_attempts << " attempts" << std::endl;
            EVP_PKEY_free(dh_keypair);
            EVP_PKEY_free(peer_dh_pubkey);
            return false;
        }
    } while (used_server_nonces.find(s_nonce) != used_server_nonces.end());

    // Aggiungi il nonce al set
    used_server_nonces.insert(s_nonce);
    // INFO
    std::cout << "INFO - Nonce successfully generated." << std::endl
              << std::endl;

    // derive the session keys and HMAC from shared secret
    // DEBUG
    // std::cout << "Deriving session keys and HMAC from shared secret..." << std::endl;
    //
    // byte_vec c_key, s_key, c_mac, s_mac;
    byte_vec salt = c_nonce;
    salt.insert(salt.end(), s_nonce.begin(), s_nonce.end());
    if (!deriveKeys(DH_shared_key, c_key, s_key, c_mac, s_mac, salt))
    {
        std::cerr << "ERROR: Failed to derive keys" << std::endl;
        EVP_PKEY_free(dh_keypair);
        EVP_PKEY_free(peer_dh_pubkey);
        return false;
    }
    // INFO
    std::cout << "INFO - Session keys and HMAC successfully derived." << std::endl
              << std::endl;

    // send the IV, nonce, DH public key, encrypted signature and HMAC to the client
    // DEBUG
    // std::cout << "Sending keys to client..." << std::endl;
    //
    if (!sendServerKeys(sock, s_priv_key, s_nonce, c_nonce, c_dh_pubkey_bin, s_dh_pubkey_bin, s_key, s_mac))
    {
        std::cerr << "ERROR: Failed to send server keys" << std::endl;
        EVP_PKEY_free(dh_keypair);
        EVP_PKEY_free(peer_dh_pubkey);
        return false;
    }
    // INFO
    std::cout << "INFO - Keys successfully sent to client." << std::endl
              << std::endl;

    // DEBUG
    // std::cout << "Waiting for ACK from client..." << std::endl;
    // wait for ACK from client
    byte_vec cmd, argument;
    if (!recvFromClientSecure(sock, cmd, argument, s_nonce, c_nonce, c_key, c_mac, used_client_nonces))
    {
        std::cerr << "ERROR: Failed to receive ACK from client" << std::endl;
        return false;
    }

    // add c_nonce to used nonces
    used_client_nonces.insert(c_nonce);

    // check ACK command size
    if (cmd.size() != CMD_SIZE)
    {
        std::cerr << "ERROR: Invalid ACK command size" << std::endl;
        return false;
    }

    // check that the command is ACK
    if (cmd != byte_vec({'A', 'C', 'K'}))
    {
        std::cerr << "ERROR: Expected ACK from client, got something else" << std::endl;
        return false;
    }

    // check that the argument is empty
    if (!argument.empty())
    {
        std::cerr << "ERROR: ACK argument is not empty" << std::endl;
        return false;
    }

    // ACK has been received correctly
    std::cout << "INFO - ACK received from client." << std::endl
              << std::endl;

    // INFO
    std::cout << "\t Handshake completed successfully. Secure channel established." << std::endl
              << std::endl;

    EVP_PKEY_free(dh_keypair);
    EVP_PKEY_free(peer_dh_pubkey);
    return true;
}

// function to hash the login user password
byte_vec hashPassword(const std::string &password, const byte_vec &salt)
{
    byte_vec hash(HASH_SIZE); // SHA-256 produces a 32-byte hash
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        return {}; // Returns an empty byte_vec in case of error
    }

    // Compute hash = SHA256(password + salt)
    if (EVP_DigestInit_ex(mdctx, HASH_ALGORITHM, NULL) != 1 ||
        EVP_DigestUpdate(mdctx, password.c_str(), password.length()) != 1 ||
        EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash.data(), NULL) != 1)
    {
        EVP_MD_CTX_free(mdctx);
        return {}; // Returns an empty byte_vec in case of error
    }

    EVP_MD_CTX_free(mdctx);
    return hash;
}

// Check credentials against employees.csv
bool checkCredentials(const std::string &username, const std::string &password)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Failed to open employees.csv" << std::endl;
        return false;
    }

    std::string line;
    // Skip the header
    if (!std::getline(infile, line))
        return false;

    while (std::getline(infile, line))
    {
        // CSV: username,password_hash,salt,first_login,keys_deleted,privateKey,publicKey
        // simple split on commas (private/public key fields may be empty)
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
        if (cols.size() < 3)
            continue;

        const std::string &u = cols[0];
        const std::string &hash_hex = cols[1];
        const std::string &salt_hex = cols[2];

        if (u == username)
        {
            byte_vec salt = fromHex(salt_hex);
            byte_vec stored_hash = fromHex(hash_hex);
            if (salt.empty() || stored_hash.empty())
            {
                std::cerr << "ERROR: Corrupted DB entry for user '" << username << "'" << std::endl;
                return false;
            }
            byte_vec calc_hash = hashPassword(password, salt);
            if (calc_hash.empty())
            {
                std::cerr << "ERROR: Hashing failed" << std::endl;
                return false;
            }
            return calc_hash == stored_hash;
        }
    }
    // user not found
    return false;
}

// Returns true if the user has first_login == 1, otherwise false.
// If the user is not found or the file cannot be opened, returns false.
bool isFirstLogin(const std::string &username)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Failed to open employees.csv" << std::endl;
        return false;
    }

    std::string line;
    // Skip the header
    if (!std::getline(infile, line))
        return false;

    while (std::getline(infile, line))
    {
        // simple split on commas (private/public key fields may be empty)
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
        if (cols.size() < 4)
            continue;

        const std::string &u = cols[0];
        const std::string &first_login = cols[3];

        if (u == username)
        {
            return first_login == "1";
        }
    }
    return false;
}

// function that manages the client authentication
// it returns 1 if authentication is successful, -1 for user/pwd errors, 0 otherwise
int authenticateClient(int sock, byte_vec &c_nonce, byte_vec &s_nonce, byte_vec &c_key, byte_vec &c_mac, byte_vec &s_key, byte_vec &s_mac, std::string &username, std::string &password,
                       std::set<byte_vec> &used_client_nonces,
                       std::set<byte_vec> &used_server_nonces)
{
    // std::cout << "Starting authentication process..." << std::endl;
    // Receive username and password from client

    byte_vec cmd, argument;
    if (!recvFromClientSecure(sock, cmd, argument, s_nonce, c_nonce, c_key, c_mac, used_client_nonces))
    {
        std::cerr << "ERROR: Failed to receive LOGIN message" << std::endl;
        return 0;
    }

    used_client_nonces.insert(c_nonce);

    if (cmd.size() != CMD_SIZE)
    {
        std::cerr << "ERROR: Invalid command size (expected " << CMD_SIZE
                  << ", got " << cmd.size() << ")" << std::endl;
        return 0;
    }

    // Check that the command is LOGIN
    if (cmd != byte_vec({'L', 'O', 'G'}))
    {
        std::cerr << "ERROR: Expected LOGIN command, got something else" << std::endl;
        std::cerr << "Received command: (";
        for (unsigned char c : cmd)
        {
            std::cerr << c;
        }
        std::cerr << ")" << std::endl;
        return 0;
    }
    // Extract username and password from argument
    size_t offset = 0;

    byte_vec username_vec, password_vec;
    if (!extract_field(username_vec, argument, offset) ||
        !extract_field(password_vec, argument, offset))
    {
        std::cerr << "ERROR: Malformed LOGIN argument (cannot extract username/password)" << std::endl;
        return 0;
    }

    // Convert username and password from byte_vec to string
    username = std::string(username_vec.begin(), username_vec.end());
    password = std::string(password_vec.begin(), password_vec.end());

    // Validate username and password
    if (!isValidUsername(username) || !isValidPassword(password))
    {
        std::cerr << "ERROR: Invalid username or password format" << std::endl;
        byte_vec ans_cmd = toBytes("ANS");
        byte_vec ans_arg = toBytes("FAIL");
        if (!sendToClientSecure(sock, ans_cmd, ans_arg, s_nonce, c_nonce, s_key, s_mac, used_server_nonces))
        {
            std::cerr << "ERROR: Failed to send authentication failure message" << std::endl;
        }
        used_server_nonces.insert(s_nonce);
        return -1;
    }

    // checking credentials from the database (employees.csv)
    if (!checkCredentials(username, password))
    {
        std::cerr << "ERROR: Invalid username or password" << std::endl;
        // send failure response to client
        byte_vec ans_cmd = toBytes("ANS");
        byte_vec ans_arg = toBytes("FAIL");
        if (!sendToClientSecure(sock, ans_cmd, ans_arg, s_nonce, c_nonce, s_key, s_mac, used_server_nonces))
        {
            std::cerr << "ERROR: Failed to send authentication failure message" << std::endl;
        }
        used_server_nonces.insert(s_nonce);
        return -1;
    }

    // INFO
    std::cout << "INFO - User '" << username << "' authenticated successfully." << std::endl;

    // send success response to client
    byte_vec ans_cmd = toBytes("ANS");

    // check if it is the first login (then ask to change the password)
    byte_vec ans_arg = {};
    if (isFirstLogin(username))
    {
        // INFO
        std::cout << "INFO - First login detected for user '" << username << "'. Requesting password change." << std::endl;
        ans_arg = toBytes("FIRST_LOGIN");
        if (!sendToClientSecure(sock, ans_cmd, ans_arg, s_nonce, c_nonce, s_key, s_mac, used_server_nonces))
        {
            std::cerr << "ERROR: Failed to send first-login notice" << std::endl;
            return 0;
        }
        used_server_nonces.insert(s_nonce);

        // now wait for the CNG command with the new password
        byte_vec cmd_cng, arg_cng;
        if (!recvFromClientSecure(sock, cmd_cng, arg_cng, s_nonce, c_nonce, c_key, c_mac, used_client_nonces))
        {
            std::cerr << "ERROR: Failed to receive CNG message" << std::endl;
            return 0;
        }
        used_client_nonces.insert(c_nonce);

        if (cmd_cng != toBytes("CNG"))
        {
            std::cerr << "ERROR: Expected CNG command, got something else" << std::endl;
            return 0;
        }

        std::string new_password;
        byte_vec new_password_vec;
        offset = 0;
        if (!extract_field(new_password_vec, arg_cng, offset))
        {
            std::cerr << "ERROR: Malformed CNG argument (cannot extract username/password)" << std::endl;
            return 0;
        }

        new_password = toString(new_password_vec);

        if (!isValidPassword(new_password))
        {
            std::cerr << "ERROR: Invalid password format during first login" << std::endl;
            byte_vec ans_cmd = toBytes("ANS");
            byte_vec ans_arg = toBytes("FAIL");
            if (!sendToClientSecure(sock, ans_cmd, ans_arg, s_nonce, c_nonce, s_key, s_mac, used_server_nonces))
            {
                std::cerr << "ERROR: Failed to send answer" << std::endl;
            }
            used_server_nonces.insert(s_nonce);
            return -1;
        }

        // check that the new password is different from the old one
        if (new_password == password)
        {
            std::cerr << "ERROR: New password cannot be the same as the old password" << std::endl;
            byte_vec ans_cmd = toBytes("ANS");
            byte_vec ans_arg = toBytes("SAME_PASSWORD");
            if (!sendToClientSecure(sock, ans_cmd, ans_arg, s_nonce, c_nonce, s_key, s_mac, used_server_nonces))
            {
                std::cerr << "ERROR: Failed to send answer" << std::endl;
            }
            used_server_nonces.insert(s_nonce);
            return -1;
        }

        if (!changeUserPassword(username, new_password))
        {
            std::cerr << "ERROR: Failed to change user password" << std::endl;
            return 0; // error of the server
        }
    }
    ans_arg = toBytes("SUCCESS");
    if (!sendToClientSecure(sock, ans_cmd, ans_arg, s_nonce, c_nonce, s_key, s_mac, used_server_nonces))
    {
        std::cerr << "ERROR: Failed to send authentication success message" << std::endl;
        return false;
    }
    used_server_nonces.insert(s_nonce);
    return true;
}

// function that check if the user has already a key pair
bool userHasKeys(const std::string &username)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Cannot open employees.csv" << std::endl;
        return false;
    }

    // DEBUG
    // std::cout << "Checking keys for user: " << username << std::endl;

    std::string line;

    // Skip header
    std::getline(infile, line);

    while (std::getline(infile, line))
    {
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        if (cols.size() < CSV_COLUMNS)
            continue;

        if (cols[0] == username)
        {
            // DEBUG
            // std::cout << "User found. Private key field: '" << cols[5] << "', Public key field: '" << cols[6] << "'" << std::endl;
            return !cols[5].empty() && !cols[6].empty();
        }
        // else
        // {
        //     // DEBUG
        //     std::cout << "Skipping user: '" << cols[0] << "'" << std::endl;
        //     std::cout << "User searched: '" << username << "'" << std::endl;
        // }
    }

    return false;
}

// function that checks if the user has deleted his keys
bool userKeysDeleted(const std::string &username)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Cannot open employees.csv" << std::endl;
        return false;
    }

    // DEBUG
    // std::cout << "Checking if keys are deleted for user: " << username << std::endl;

    std::string line;

    // Skip header
    std::getline(infile, line);

    while (std::getline(infile, line))
    {
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        if (cols.size() < 5)
            continue;

        if (cols[0] == username)
        {
            return cols[4] == "1";
        }
    }

    return false;
}

// function that creates and stores a pair of private and public keys on behalf of the invoking user.
// If a key pair is already existing for the user, the operation has no effect.
// if a user has keys_deleted == 1, new keys are not created
bool createUserKeys(const std::string &username, const byte_vec &DSS_MASTER_KEY)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Cannot open employees.csv" << std::endl;
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    bool found = false;

    // Save header
    std::getline(infile, line);
    lines.push_back(line);

    while (std::getline(infile, line))
    {
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        if (cols.size() < CSV_COLUMNS)
        {
            lines.push_back(line);
            continue;
        }

        if (cols[0] == username)
        {
            found = true;

            // If keys already exist → no effect
            if (!cols[5].empty() || !cols[6].empty())
            {
                // std::cout << "DEBUG: Keys already exist for user " << username << std::endl;
                return true;
            }

            // Se keys_deleted == 1 → no new keys
            if (cols[4] == "1")
            {
                // std::cerr << "DEBUG: User " << username << " has deleted keys; no new keys will be created" << std::endl;
                return false;
            }

            // ====== RSA KEY GENERATION ======
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
            EVP_PKEY *pkey = nullptr;

            if (!ctx ||
                EVP_PKEY_keygen_init(ctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0 ||
                EVP_PKEY_keygen(ctx, &pkey) <= 0)
            {
                EVP_PKEY_CTX_free(ctx);
                std::cerr << "ERROR: RSA key generation failed" << std::endl;
                return false;
            }
            EVP_PKEY_CTX_free(ctx);

            // ====== SERIALIZE PUBLIC KEY ======
            unsigned char *pub_der = nullptr;
            int pub_len = i2d_PUBKEY(pkey, &pub_der);
            if (pub_len <= 0)
            {
                EVP_PKEY_free(pkey);
                return false;
            }
            byte_vec pubkey(pub_der, pub_der + pub_len);
            OPENSSL_free(pub_der);

            // ====== SERIALIZE PRIVATE KEY ======
            unsigned char *priv_der = nullptr;
            int priv_len = i2d_PrivateKey(pkey, &priv_der);
            EVP_PKEY_free(pkey);
            if (priv_len <= 0)
                return false;

            byte_vec privkey(priv_der, priv_der + priv_len);
            OPENSSL_free(priv_der);

            // ====== ENCRYPT PRIVATE KEY WITH MASTER KEY ======
            byte_vec iv(IV_SIZE);
            RAND_bytes(iv.data(), iv.size());

            byte_vec encrypted_priv;
            if (!cbcEncrypt(privkey, DSS_MASTER_KEY, iv, encrypted_priv))
            {
                std::cerr << "ERROR: Failed to encrypt private key" << std::endl;
                return false;
            }

            // ====== SAVE IN CSV ======
            cols[5] = toHex(iv) + ":" + toHex(encrypted_priv);
            cols[6] = toHex(pubkey);

            std::string new_line = cols[0];
            for (size_t i = 1; i < cols.size(); ++i)
                new_line += "," + cols[i];

            lines.push_back(new_line);
        }
        else
        {
            lines.push_back(line);
        }
    }

    infile.close();

    if (!found)
    {
        std::cerr << "ERROR: User not found" << std::endl;
        return false;
    }

    // ====== REWRITE FILE ======
    std::ofstream out(EMPLOYEES_DB_FILE, std::ios::trunc);
    for (const auto &l : lines)
        out << l << "\n";
    out.close();

    std::cout << "INFO - Key pair created successfully for " << username << std::endl;
    return true;
}

// function that search all the users with a public key and list them
bool listUsersWithPublicKey(std::vector<std::string> &usernames)
{
    usernames.clear();

    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Cannot open employees.csv" << std::endl;
        return false;
    }

    std::string line;

    // Skip header
    if (!std::getline(infile, line))
    {
        return false;
    }

    while (std::getline(infile, line))
    {
        std::vector<std::string> cols;
        size_t start = 0;

        // Simple CSV parsing
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        // Check number of columns
        if (cols.size() < CSV_COLUMNS)
            continue;

        const std::string &username = cols[0];
        const std::string &publicKey = cols[6];

        if (!publicKey.empty())
        {
            usernames.push_back(username);
        }
    }

    infile.close();
    return true;
}

// function that deletes the keys of the invoking user and set keys_deleted to 1
bool deleteUserKeys(const std::string &username)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Cannot open employees.csv" << std::endl;
        return false;
    }

    std::vector<std::string> lines;
    std::string line;
    bool found = false;

    // Save header
    std::getline(infile, line);
    lines.push_back(line);

    while (std::getline(infile, line))
    {
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        if (cols.size() < CSV_COLUMNS)
        {
            lines.push_back(line);
            continue;
        }

        if (cols[0] == username)
        {
            found = true;

            // Delete keys and set keys_deleted to 1
            cols[5] = "";
            cols[6] = "";
            cols[4] = "1"; // keys_deleted = 1

            std::string new_line = cols[0];
            for (size_t i = 1; i < cols.size(); ++i)
                new_line += "," + cols[i];

            lines.push_back(new_line);
        }
        else
        {
            lines.push_back(line);
        }
    }

    infile.close();

    if (!found)
    {
        std::cerr << "ERROR: User not found" << std::endl;
        return false;
    }

    // ====== REWRITE FILE ======
    std::ofstream out(EMPLOYEES_DB_FILE, std::ios::trunc);
    for (const auto &l : lines)
        out << l << "\n";
    out.close();

    std::cout << "INFO - Keys deleted successfully for " << username << std::endl;
    return true;
}

// function that signs a document on behalf of the invoking user
bool signDocument(const std::string &username,
                  const std::string &filename,
                  const byte_vec &DSS_MASTER_KEY,
                  byte_vec &signature_out)
{
    EVP_PKEY *privkey = loadUserPrivateKey(username, DSS_MASTER_KEY);
    if (!privkey)
        return false;

    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        EVP_PKEY_free(privkey);
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, HASH_ALGORITHM, nullptr, privkey);

    char buf[4096];
    while (file.read(buf, sizeof(buf)) || file.gcount())
        EVP_DigestSignUpdate(ctx, buf, file.gcount());

    size_t siglen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &siglen);
    signature_out.resize(siglen);
    EVP_DigestSignFinal(ctx, signature_out.data(), &siglen);
    signature_out.resize(siglen);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privkey);
    return true;
}

// function that verifies a document signature
bool verifySignature(const std::string &signer_username,
                     const std::string &filename,
                     const byte_vec &signature)
{
    EVP_PKEY *pubkey = loadUserPublicKey(signer_username);
    if (!pubkey)
        return false;

    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        EVP_PKEY_free(pubkey);
        return false;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, HASH_ALGORITHM, nullptr, pubkey);

    char buf[4096];
    while (file.read(buf, sizeof(buf)) || file.gcount())
        EVP_DigestVerifyUpdate(ctx, buf, file.gcount());

    int ok = EVP_DigestVerifyFinal(ctx,
                                   signature.data(),
                                   signature.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return ok == 1;
}

// function that checks if the username exists in the database
bool userExists(const std::string &username)
{
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Cannot open employees.csv" << std::endl;
        return false;
    }

    std::string line;

    // Skip header
    if (!std::getline(infile, line))
        return false;

    while (std::getline(infile, line))
    {
        // Simple CSV parsing (same method used in other functions)
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }

        if (cols.empty())
            continue;

        if (cols[0] == username)
        {
            return true;
        }
    }
    return false;
}

// function that checks if the file exists and is readable
bool fileExists(const std::string &filename)
{
    std::ifstream file(filename);
    return file.good();
}

// function that manages the client
void gestisci_client(int client_sock, EVP_PKEY *s_privkey, const byte_vec &DSS_MASTER_KEY)
{
    char buffer[1024];
    byte_vec c_nonce, s_nonce, c_key, c_mac, s_key, s_mac;
    std::string username, password;

    // set useful to memorize the nonces already used in this session
    std::set<byte_vec> used_client_nonces;
    std::set<byte_vec> used_server_nonces;

    // start the HANDSHAKE to make the SECURE CHANNEL
    std::cout << "\t Starting handshake to create secure channel with a new client." << std::endl;
    if (!handshakeSecureChannelServer(client_sock, s_privkey, c_nonce, s_nonce, c_key, c_mac, s_key, s_mac, used_client_nonces, used_server_nonces))
    {
        std::cerr << "ERROR: Handshake failed\n";
        close(client_sock);
        return;
    }
    // used nonces sets updated inside the function

    // AUTHENTICATION
    std::cout << "Starting authentication with a new client." << std::endl;
    int auth_success = -1;
    while (auth_success == -1)
    {
        auth_success = authenticateClient(client_sock, c_nonce, s_nonce, c_key, c_mac, s_key, s_mac, username, password, used_client_nonces, used_server_nonces);
        if (auth_success == -1)
        {
            std::cout << "Authentication failed for client " << client_sock << ". Retrying..." << std::endl;
        }
    }

    // INFO
    std::cout << "INFO - Client " << username << " authenticated successfully." << std::endl
              << std::endl;
    while (true)
    {
        // receive messages from client
        byte_vec cmd, argument;
        if (!recvFromClientSecure(client_sock, cmd, argument, s_nonce, c_nonce, c_key, c_mac, used_client_nonces))
        {
            // DEBUG-ERROR
            // std::cerr << "ERROR: Failed to receive secure message from client at socket " << client_sock << std::endl;

            break;
        }

        used_client_nonces.insert(c_nonce);

        if (cmd.size() != CMD_SIZE)
        {
            std::cerr << "ERROR: Invalid command size from client " << client_sock << std::endl;
            break;
        }

        if (cmd == toBytes("EXT"))
        {
            std::cout << "Client " << username << " requested to close the connection." << std::endl;
            break;
        }

        // process the received command
        byte_vec response_cmd = toBytes("ANS");
        byte_vec response_arg = {};

        // DEBUG: print received command
        // std::string cmd_str = toString(cmd);
        // std::cout << "Received command from client " << client_sock << ": " << cmd_str << std::endl;
        // // For now, just echo back the received command and argument
        // response_arg = toBytes("Received command: " + cmd_str + ", argument length: " + std::to_string(argument.size()));

        // command processing
        if (cmd == toBytes("HLP"))
        {
            response_arg = toBytes("Available commands: \n"
                                   "HLP - Show this help message \n"
                                   "CNG - Change password \n"
                                   "CRT - Create public and private keys, if not existing \n"
                                   "LST - List users with a public key \n"
                                   "GET - Get public key of a user \n"
                                   "SGN - Apply digital signature to a document \n"
                                   "VRF - Verify a digital signature \n"
                                   "DEL - Delete keys \n"
                                   "EXT - Terminate the connection \n");
        }
        else if (cmd == toBytes("CNG")) // change password
        {
            // new password is in argument
            std::string new_password;
            byte_vec new_password_vec;
            size_t offset = 0;

            if (!extract_field(new_password_vec, argument, offset))
            {
                response_arg = toBytes("Malformed CNG argument (password)\n");
            }
            else
            {
                std::string new_password = toString(new_password_vec);

                if (!isValidPassword(new_password))
                {
                    response_arg = toBytes("Invalid password format (too long or contains invalid characters)\n");
                }
                else if (!changeUserPassword(username, new_password))
                {
                    std::cerr << "ERROR: Failed to change user password" << std::endl;
                    response_arg = toBytes("Failed to change your password");
                }
                else
                {
                    response_arg = toBytes("Password changed successfully\n");
                }
            }
        }
        else if (cmd == toBytes("CRT"))
        {
            if (userHasKeys(username))
            {
                response_arg = toBytes("Keys already exist\n");
            }
            else if (userKeysDeleted(username))
            {
                response_arg = toBytes("Keys have been deleted; no new keys can be created\n");
            }
            else if (createUserKeys(username, DSS_MASTER_KEY))
            {
                response_arg = toBytes("A new key pair has been created!\n");
            }
            else
            {
                response_arg = toBytes("Failed to create key pair\n");
            }
        }
        else if (cmd == toBytes("LST"))
        {
            std::vector<std::string> usernames_list;
            if (listUsersWithPublicKey(usernames_list))
            {
                // check if list is empty
                if (usernames_list.empty())
                {
                    response_arg = toBytes("No users with public keys found\n");
                }
                else
                {
                    std::string user_list = "Users with public keys:\n";
                    for (const auto &user : usernames_list)
                    {
                        user_list += "- " + user + "\n";
                    }
                    response_arg = toBytes(user_list);
                }
            }
            else
            {
                response_arg = toBytes("Failed to list users with public keys\n");
            }
        }
        else if (cmd == toBytes("GET"))
        {
            std::string target_username;
            byte_vec target_username_vec;
            size_t offset = 0;
            // argument contains the target username
            if (!extract_field(target_username_vec, argument, offset))
            {
                response_arg = toBytes("Malformed GET argument (username)\n");
            }
            else
            {
                target_username = toString(target_username_vec);

                if (!isValidUsername(target_username))
                {
                    response_arg = toBytes("Invalid username format\n");
                }
                else if (!userExists(target_username)) // Check if user exists in database
                {
                    response_arg = toBytes("User '" + target_username + "' does not exist\n");
                }
                else
                {
                    // check if user has keys
                    if (!userHasKeys(target_username))
                    {
                        if (userKeysDeleted(target_username))
                        {
                            response_arg = toBytes("The keys of the user '" + target_username + "' have been deleted\n");
                        }
                        else
                        {
                            response_arg = toBytes("User '" + target_username + "' has not created keys yet\n");
                        }
                    }
                    else
                    {
                        EVP_PKEY *pubkey = loadUserPublicKey(target_username);
                        if (!pubkey)
                        {
                            response_arg = toBytes("Failed to load public key for user " + target_username + "\n");
                        }
                        else
                        {
                            // serialize public key to DER
                            unsigned char *pub_der = nullptr;
                            int pub_len = i2d_PUBKEY(pubkey, &pub_der);
                            EVP_PKEY_free(pubkey);
                            if (pub_len <= 0)
                            {
                                response_arg = toBytes("Failed to serialize public key for user " + target_username + "\n");
                            }
                            else
                            {
                                byte_vec pubkey_vec(pub_der, pub_der + pub_len);
                                OPENSSL_free(pub_der);
                                response_arg = toBytes("Public key for user " + target_username + " (DER format, hex-encoded):\n");
                                std::string pubkey_hex = toHex(pubkey_vec);
                                response_arg.insert(response_arg.end(), pubkey_hex.begin(), pubkey_hex.end());
                                response_arg.push_back('\n');
                            }
                        }
                    }
                }
            }
        }
        else if (cmd == toBytes("SGN"))
        {
            if (!userHasKeys(username))
            {
                response_arg = toBytes("You do not have keys to sign documents\n");
            }
            else
            {
                // argument contains the filename to sign
                std::string filename;
                byte_vec filename_vec;
                size_t offset = 0;
                if (!extract_field(filename_vec, argument, offset))
                {
                    response_arg = toBytes("Malformed SGN argument (filename)\n");
                }
                else
                {
                    filename = toString(filename_vec);
                    if (!fileExists(filename))
                    {
                        response_arg = toBytes("The specified file does not exist or is not readable\n");
                    }
                    else
                    {
                        byte_vec signature;
                        if (signDocument(username, filename, DSS_MASTER_KEY, signature))
                        {
                            response_arg = toBytes("Document signed successfully; the signature is:\n");
                            // convert signature to hex
                            std::string signature_hex = toHex(signature);
                            response_arg.insert(response_arg.end(), signature_hex.begin(), signature_hex.end());
                            response_arg.push_back('\n');
                        }
                        else
                        {
                            response_arg = toBytes("Failed to sign document\n");
                        }
                    }
                }
            }
        }
        else if (cmd == toBytes("VRF"))
        {
            // argument contains the filename to sign, the username and the signature
            std::string filename;
            byte_vec filename_vec;
            size_t offset = 0;
            if (!extract_field(filename_vec, argument, offset))
            {
                response_arg = toBytes("Malformed SGN argument (filename)\n");
            }
            else
            {
                filename = toString(filename_vec);
                if (!fileExists(filename))
                {
                    response_arg = toBytes("The specified file does not exist or is not readable\n");
                }
                else
                {
                    // extract signer username
                    std::string signer_username;
                    byte_vec username_vec;
                    if (!extract_field(username_vec, argument, offset))
                    {
                        response_arg = toBytes("Malformed SGN argument (username)\n");
                    }
                    else
                    {
                        // check if signer_username exists
                        if (!userExists(toString(username_vec)))
                        {
                            response_arg = toBytes("The signer username does not exist\n");
                        }
                        else
                        {
                            signer_username = toString(username_vec);
                            // check if signer_username has keys
                            if (!userHasKeys(signer_username))
                            {
                                // check if keys were been deleted
                                if (userKeysDeleted(signer_username))
                                {
                                    response_arg = toBytes("The keys of the signer user have been deleted\n");
                                }
                                else
                                {
                                    response_arg = toBytes("The signer user has not created keys yet\n");
                                }
                            }
                            else
                            {
                                byte_vec signature;
                                if (!extract_field(signature, argument, offset))
                                {
                                    response_arg = toBytes("Malformed SGN argument (signature)\n");
                                }
                                else
                                {
                                    if (verifySignature(signer_username, filename, signature))
                                    {
                                        response_arg = toBytes("Signature is VALID\n");
                                    }
                                    else
                                    {
                                        response_arg = toBytes("Signature is INVALID\n");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else if (cmd == toBytes("DEL"))
        {
            if (userKeysDeleted(username))
            {
                response_arg = toBytes("Keys have already been deleted\n");
            }
            else if (!userHasKeys(username))
            {
                response_arg = toBytes("No keys to delete\n");
            }
            else if (deleteUserKeys(username))
            {
                response_arg = toBytes("Keys deleted successfully\n");
            }
            else
            {
                response_arg = toBytes("Failed to delete keys\n");
            }
        }
        else
        {
            response_arg = toBytes("Unknown command");
        }

        // send response back to client
        if (!sendToClientSecure(client_sock, response_cmd, response_arg, s_nonce, c_nonce, s_key, s_mac, used_server_nonces))
        {
            std::cerr << "ERROR: Failed to send response to client " << client_sock << std::endl;
            break;
        }
        used_server_nonces.insert(s_nonce);
    }
    close(client_sock);
}

// function for sending encrypted and authenticated messages
bool sendToClientSecure(int sock, const byte_vec &cmd, const byte_vec &argument,
                        byte_vec &s_nonce, byte_vec &c_nonce,
                        const byte_vec &s_key, const byte_vec &s_mac,
                        std::set<byte_vec> &used_server_nonces)
{
    // dimensioning nonces if they are empty
    if (s_nonce.size() == 0)
        s_nonce.resize(NONCE_SIZE);
    if (c_nonce.size() == 0)
        c_nonce.resize(NONCE_SIZE);

    // 1) Generate the server nonce
    byte_vec new_s_nonce(NONCE_SIZE);
    int max_attempts = 500;
    int attempts = 0;

    // generate a nonce that has not been used before
    do
    {
        if (RAND_bytes(new_s_nonce.data(), new_s_nonce.size()) != 1)
        {
            std::cerr << "ERROR: Failed to generate server nonce" << std::endl;
            return false;
        }
        attempts++;
        if (attempts >= max_attempts)
        {
            std::cerr << "ERROR: Failed to generate unique nonce after " << max_attempts << " attempts" << std::endl;
            return false;
        }
    } while (used_server_nonces.find(new_s_nonce) != used_server_nonces.end());

    s_nonce = new_s_nonce;

    // 2) Compose plaintext: [len][s_nonce][len][c_nonce][len][cmd][len][argument]
    byte_vec msg;
    push_field(msg, s_nonce);
    push_field(msg, c_nonce);
    push_field(msg, cmd);
    push_field(msg, argument);

    // 3) Encrypt with s_key and random IV
    byte_vec ciphertext;
    byte_vec iv(IV_SIZE);
    if (RAND_bytes(iv.data(), iv.size()) != 1)
    {
        std::cerr << "ERROR: Failed to generate IV" << std::endl;
        return false;
    }
    if (!cbcEncrypt(msg, s_key, iv, ciphertext))
    {
        std::cerr << "ERROR: Failed to encrypt message" << std::endl;
        return false;
    }
    msg.clear();

    // 4) HMAC su [IV][ciphertext]
    byte_vec to_authenticate;
    push_field(to_authenticate, iv);
    push_field(to_authenticate, ciphertext);

    byte_vec hmac(HMAC_SIZE);
    if (!computeHMAC(s_mac, to_authenticate, hmac))
    {
        std::cerr << "ERROR: Failed to compute HMAC" << std::endl;
        return false;
    }
    hmac.resize(HMAC_SIZE);

    // 5) Send [IV][ciphertext][HMAC]
    msg = to_authenticate;
    push_field(msg, hmac);
    if (send_msg(sock, reinterpret_cast<const char *>(msg.data()), msg.size()) != (ssize_t)msg.size())
    {
        std::cerr << "ERROR: Failed to send secure message" << std::endl;
        return false;
    }
    return true;
}

// function for receiving encrypted and authenticated messages
bool recvFromClientSecure(int sock, byte_vec &cmd, byte_vec &argument,
                          byte_vec &s_nonce, byte_vec &c_nonce,
                          const byte_vec &c_key, const byte_vec &c_mac,
                          std::set<byte_vec> &used_client_nonces)
{
    // 1. Receive the message
    byte_vec buffer(BUFFER_SIZE);
    ssize_t n = recv_msg(sock, reinterpret_cast<char *>(buffer.data()), buffer.size());
    if (n < 0)
    {
        std::cerr << "ERROR: Failed to receive secure message" << std::endl;
        return false;
    }
    else if (n == 0)
    {
        std::cout << "Connection closed by the client" << std::endl;
        return false;
    }

    // 2. Extract IV, ciphertext, HMAC
    if (buffer.size() < IV_SIZE + HMAC_SIZE)
    {
        std::cerr << "ERROR: Malformed secure message" << std::endl;
        return false;
    }

    buffer.resize(n);

    // Extract fields using extract_field
    size_t offset = 0;
    byte_vec iv, ciphertext, hmac_received;

    if (!extract_field(iv, buffer, offset) ||
        !extract_field(ciphertext, buffer, offset) ||
        !extract_field(hmac_received, buffer, offset))
    {
        std::cerr << "ERROR: Failed to extract fields from message" << std::endl;
        return false;
    }

    // 3. Verify HMAC
    byte_vec to_authenticate;
    push_field(to_authenticate, iv);
    push_field(to_authenticate, ciphertext);
    byte_vec hmac_calc;
    if (!computeHMAC(c_mac, to_authenticate, hmac_calc))
    {
        std::cerr << "ERROR: Failed to compute HMAC" << std::endl;
        return false;
    }
    hmac_calc.resize(HMAC_SIZE);
    // Constant-time comparison to prevent timing attacks
    if (hmac_calc.size() != hmac_received.size() ||
        CRYPTO_memcmp(hmac_calc.data(), hmac_received.data(), HMAC_SIZE) != 0)
    {
        std::cerr << "ERROR: HMAC verification failed" << std::endl;
        return false;
    }

    // 4. Decrypt the message
    byte_vec plaintext;
    if (!cbcDecrypt(ciphertext, c_key, iv, plaintext))
    {
        std::cerr << "ERROR: Failed to decrypt message" << std::endl;
        return false;
    }

    // 5. Extract fields from plaintext
    offset = 0;
    byte_vec s_nonce_received, c_nonce_received;
    if (!extract_field(s_nonce_received, plaintext, offset) ||
        !extract_field(c_nonce_received, plaintext, offset) ||
        !extract_field(cmd, plaintext, offset) ||
        !extract_field(argument, plaintext, offset))
    {
        std::cerr << "ERROR: Malformed plaintext" << std::endl;
        return false;
    }

    // nonces control
    if (s_nonce_received != s_nonce)
    {
        std::cerr << "ERROR: Server nonce mismatch" << std::endl;
        return false;
    }

    if (used_client_nonces.find(c_nonce_received) != used_client_nonces.end())
    {
        std::cerr << "ERROR: Replay attack detected (client nonce already used in this session)" << std::endl;
        return false;
    }

    // check command size
    if (cmd.size() != CMD_SIZE)
    {
        std::cerr << "ERROR: Invalid command size (expected " << CMD_SIZE
                  << ", got " << cmd.size() << ")" << std::endl;
        return false;
    }

    // 6. update the nonce
    // it will be put in the used nonces set in the calling function
    c_nonce = c_nonce_received;

    return true;
}

// Function to convert a byte_vec to a hexadecimal string
std::string toHex(const byte_vec &data)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : data)
    {
        ss << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

// function to change the password of an user
bool changeUserPassword(const std::string &username, const std::string &new_password)
{
    if (!isValidPassword(new_password))
    {
        std::cerr << "ERROR: Invalid password format" << std::endl;
        return false;
    }
    // update the salt and the password hash
    byte_vec new_salt(SALT_SIZE);
    if (!RAND_bytes(new_salt.data(), new_salt.size()))
    {
        std::cerr << "ERROR: Failed to generate new salt" << std::endl;
        return false;
    }
    byte_vec new_hash = hashPassword(new_password, new_salt);
    if (new_hash.empty())
    {
        std::cerr << "ERROR: Failed to hash new password" << std::endl;
        return false;
    }
    std::string new_hash_hex = toHex(new_hash);
    std::string new_salt_hex = toHex(new_salt);

    // read, modify and rewrite employees.csv
    std::ifstream infile(EMPLOYEES_DB_FILE);
    if (!infile.is_open())
    {
        std::cerr << "ERROR: Failed to open employees.csv for reading" << std::endl;
        return false;
    }

    std::stringstream outContent;
    std::string line;

    // copy header
    if (!std::getline(infile, line))
    {
        infile.close();
        std::cerr << "ERROR: Empty employees.csv" << std::endl;
        return false;
    }
    outContent << line << "\n";

    bool updated = false;
    while (std::getline(infile, line))
    {
        // simple split on comma
        std::vector<std::string> cols;
        size_t start = 0;
        while (true)
        {
            size_t pos = line.find(',', start);
            if (pos == std::string::npos)
            {
                cols.push_back(line.substr(start));
                break;
            }
            cols.push_back(line.substr(start, pos - start));
            start = pos + 1;
        }
        if (cols.size() < CSV_COLUMNS)
        {
            // invalid row, keep it as is
            outContent << line << "\n";
            continue;
        }

        if (cols[0] == username)
        {
            cols[1] = new_hash_hex; // password_hash
            cols[2] = new_salt_hex; // salt
            cols[3] = "0";          // first_login -> 0

            outContent << cols[0] << "," << cols[1] << "," << cols[2] << "," << cols[3]
                       << "," << cols[4] << "," << cols[5] << "," << cols[6] << "\n";
            updated = true;
        }
        else
        {
            outContent << line << "\n";
        }
    }
    infile.close();

    if (!updated)
    {
        std::cerr << "ERROR: User not found in employees.csv" << std::endl;
        return false;
    }

    std::ofstream outfile(EMPLOYEES_DB_FILE, std::ios::trunc);
    if (!outfile.is_open())
    {
        std::cerr << "ERROR: Failed to open employees.csv for writing" << std::endl;
        return false;
    }
    outfile << outContent.str();
    outfile.close();

    // INFO
    std::cout << "INFO - Password updated successfully for user '" << username << "'." << std::endl;
    return true;
}

/*

-----------------------------------MAIN-----------------------------------------

*/
int main(int argc, char *argv[])
{
    if (argc == 2)
    {
        if (strcmp(argv[1], "reset") == 0)
        {
            // reset the employees database
            // create an object to write to file in truncation mode
            // if it exists it overwrites it, if it doesn't it creates it
            std::ofstream ofs(EMPLOYEES_DB_FILE, std::ofstream::trunc);
            if (!ofs)
            {
                std::cerr << "ERROR: Could not open employees_db.csv for writing." << std::endl;
                return 1;
            }
            // Write the CSV header
            ofs << "username,password_hash,salt,first_login,keys_deleted,privateKey,publicKey\n";
            const std::vector<std::pair<std::string, std::string>> users = {
                {"alice", "alice"},
                {"bob", "bob"},
                {"charlie", "charlie"}};

            for (const auto &user : users)
            {
                // Generate a NEW salt for EACH user
                byte_vec salt(16);
                if (!RAND_bytes(salt.data(), salt.size()))
                {
                    std::cerr << "Error generating salt for " << user.first << std::endl;
                    continue;
                }

                byte_vec hashed_password = hashPassword(user.second, salt);
                if (hashed_password.empty())
                {
                    std::cerr << "Error hashing password for " << user.first << std::endl;
                    continue;
                }

                // Writes the complete row in the CSV
                ofs << user.first << ","
                    << toHex(hashed_password) << ","
                    << toHex(salt) << ","
                    << "1,0,,\n";
            }
            ofs.close();
            std::cout << std::endl
                      << "Employees database reset successfully." << std::endl
                      << std::endl;
        }
        else
        {
            std::cerr << "Usage: " << argv[0] << " [reset]" << std::endl;
            return 1;
        }
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0)
    {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    // abilitation of SO_REUSEADDR. to avoid "Address already in use" error on restart
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    //

    if (bind(server_sock, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        return 1;
    }

    if (listen(server_sock, SERVER_BACKLOG) < 0)
    {
        perror("listen");
        return 1;
    }

    std::cout << "Server listening on port " << SERVER_PORT << "..." << std::endl
              << std::endl;

    std::vector<std::thread> threads;

    // std::cout << "Loading server DH public key from file PEM..." << std::endl;
    EVP_PKEY *s_privkey = loadServerPrivKey(SERVER_PRIV_KEY_FILE);
    if (!s_privkey)
    {
        std::cerr << "FATAL ERROR: Could not load server private key" << std::endl;
        close(server_sock);
        return 1;
    }
    std::cout << "INFO - Server private key loaded successfully." << std::endl;

    // std::cout << "Loading DSS master key from file..." << std::endl;
    byte_vec DSS_MASTER_KEY = loadDssMasterKey(DSS_MASTER_KEY_FILE);
    if (DSS_MASTER_KEY.empty())
    {
        std::cerr << "FATAL ERROR: Could not load DSS master key" << std::endl;
        EVP_PKEY_free(s_privkey);
        close(server_sock);
        return 1;
    }
    std::cout << "INFO - DSS master key loaded successfully." << std::endl
              << std::endl;

    while (true)
    {
        sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (sockaddr *)&client_addr, &client_len);
        if (client_sock < 0)
        {
            perror("accept");
            continue;
        }
        std::thread(gestisci_client, client_sock, s_privkey, std::cref(DSS_MASTER_KEY)).detach();
    }
    EVP_PKEY_free(s_privkey);
    close(server_sock);
    return 0;
}
