#include <iostream>       // For std::cout, std::cerr, std::cin (console I/O)
#include <cstring>        // For memcpy, strcmp (C-style string operations)
#include <netinet/in.h>   // For sockaddr_in, htons (network structures and byte order)
#include <arpa/inet.h>    // For inet_pton (IP address conversion)
#include <sstream>        // For std::stringstream (string manipulation)
#include <openssl/pem.h>  // For PEM_read_PUBKEY (reading PEM keys)
#include <openssl/err.h>  // For ERR_print_errors_fp (OpenSSL error handling)
#include <openssl/rand.h> // For RAND_bytes (secure random number generation)
#include <cctype>         // For ::isspace (character classification)
#include <algorithm>      // For std::remove_if (algorithm utilities)

#include "utility.h"

// helper functions

// check if a string contains spaces or tabs
bool containsSpace(const std::string &str)
{
    return str.find(' ') != std::string::npos ||
           str.find('\t') != std::string::npos;
}

// read input without spaces with automatic retry
std::string readInputNoSpaces(const std::string &prompt, size_t max_length)
{
    std::string input;
    while (true)
    {
        std::cout << prompt;

        if (std::cin.peek() == '\n')
        {
            std::cin.ignore();
        }
        std::getline(std::cin, input);

        if (input.empty())
        {
            std::cout << "Input cannot be empty. Please try again.\n\n";
            continue;
        }

        if (input.length() > max_length)
        {
            std::cout << "Input too long (max " << max_length << " characters). Please try again.\n\n";
            continue;
        }

        if (containsSpace(input))
        {
            std::cout << "Input cannot contain spaces. Please try again.\n\n";
            continue;
        }

        return input;
    }
}

// function that loads the server public key from a file PEM
EVP_PKEY *loadServerPubKey(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        perror("fopen");
        return nullptr;
    }

    EVP_PKEY *s_pkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!s_pkey)
    {
        ERR_print_errors_fp(stderr);
    }
    return s_pkey;
}

// declaration
// function for receiving encrypted and authenticated messages
bool recvFromServerSecure(int sock, byte_vec &cmd, byte_vec &argument,
                          byte_vec &c_nonce, byte_vec &s_nonce,
                          const byte_vec &s_key, const byte_vec &s_mac,
                          std::set<byte_vec> &used_server_nonces);

bool receiveServerKeys(int sock, byte_vec &s_nonce, byte_vec &c_nonce_rec, byte_vec &s_dh_pub_bin,
                       byte_vec &iv, byte_vec &enc_sig, byte_vec &hmac_rec)
{
    // Receive the entire message
    byte_vec buffer(BUFFER_SIZE); // reasonable maximum size
    ssize_t n = recv_msg(sock, reinterpret_cast<char *>(buffer.data()), buffer.size());
    if (n <= 0)
    {
        std::cerr << "ERROR: Failed to receive server keys bundle" << std::endl;
        return false;
    }
    buffer.resize(n);

    size_t offset = 0;
    byte_vec signature;
    byte_vec c_nonce_received;

    if (
        !extract_field(s_nonce, buffer, offset) ||
        !extract_field(c_nonce_rec, buffer, offset) ||
        !extract_field(s_dh_pub_bin, buffer, offset) ||
        !extract_field(iv, buffer, offset) ||
        !extract_field(enc_sig, buffer, offset) ||
        !extract_field(hmac_rec, buffer, offset))
    {
        std::cerr << "ERROR: Malformed server keys bundle" << std::endl;
        return false;
    }

    return true;
}

// only declaration
// function for sending encrypted and authenticated messages
bool sendToServerSecure(int sock, const byte_vec &cmd, const byte_vec &argument,
                        byte_vec &c_nonce, byte_vec &s_nonce,
                        const byte_vec &c_key, const byte_vec &c_mac,
                        std::set<byte_vec> &used_client_nonces);

// function that includes all the operations for the handshake
// for the creation of the secure channel client side
// s_pubkey: public key of the server (not DH key)
bool handshakeSecureChannelClient(int sock, EVP_PKEY *s_pubkey, byte_vec &c_nonce, byte_vec &s_nonce,
                                  byte_vec &c_key, byte_vec &c_mac, byte_vec &s_key, byte_vec &s_mac,
                                  std::set<byte_vec> &used_client_nonces, std::set<byte_vec> &used_server_nonces)
{
    EVP_PKEY *dh_keypair = nullptr;
    byte_vec c_dh_pubkey_bin;
    // DEBUG
    // std::cout << "\nDEBUG: generating DH keypair" << std::endl;

    // generation of DH keypair
    if (!generate_dh_keys(&dh_keypair))
    {
        std::cerr << "ERROR: Failed to generate DH keypair" << std::endl;
        return false;
    }

    // INFO
    std::cout << "INFO - DH key pair successfully generated." << std::endl
              << std::endl;

    // extraction of the client DH public key from the keypair
    if (!extract_dh_public_key_der(dh_keypair, c_dh_pubkey_bin))
    {
        std::cerr << "ERROR: Failed to extract DH public key" << std::endl;
        EVP_PKEY_free(dh_keypair);
        return false;
    }

    // generation of the client nonce
    // first generation, it doesn't need the control of uniqueness
    c_nonce.resize(NONCE_SIZE);
    if (RAND_bytes(c_nonce.data(), c_nonce.size()) != 1)
    {
        std::cerr << "ERROR: Failed to generate client nonce" << std::endl;
        EVP_PKEY_free(dh_keypair);
        return false;
    }
    used_client_nonces.insert(c_nonce);

    // sending the client DH public key to the server
    // DEBUG
    // std::cout << "DEBUG: sending client DH public key to server" << std::endl;
    //
    // Prepare the message:
    byte_vec msg;
    push_field(msg, c_nonce);
    push_field(msg, c_dh_pubkey_bin);

    // Invia il messaggio al server
    if (send_msg(sock, reinterpret_cast<const char *>(msg.data()), msg.size()) != (ssize_t)msg.size())
    {
        std::cerr << "ERROR: Failed to send nonce and DH public key" << std::endl;
        EVP_PKEY_free(dh_keypair);
        return false;
    }
    // INFO
    std::cout << "INFO - Client public DH key successfully sent." << std::endl
              << std::endl;

    // receive the DH public key, the session keys and HMAC from the server
    // DEBUG
    // std::cout << "Receiving keys (nonce, public key) from server..." << std::endl;
    //

    byte_vec c_nonce_rec, s_dh_pubkey_bin, iv, enc_sig, hmac_rec;
    if (!receiveServerKeys(sock, s_nonce, c_nonce_rec, s_dh_pubkey_bin, iv, enc_sig, hmac_rec))
    {
        std::cerr << "ERROR: Failed to receive server keys" << std::endl;
        EVP_PKEY_free(dh_keypair);
        return false;
    }

    // client nonce check
    if (c_nonce_rec != c_nonce)
    {
        std::cerr << "ERROR: Client nonce mismatch in handshake!" << std::endl;
        return false;
    }

    // Compute the DH shared key (shared secret)
    byte_vec shared_secret;
    if (!generate_dh_shared_key(dh_keypair, s_dh_pubkey_bin, shared_secret))
    {
        std::cerr << "ERROR: Failed to derive DH shared key" << std::endl;
        EVP_PKEY_free(dh_keypair);
        return false;
    }
    EVP_PKEY_free(dh_keypair);

    // Derive session and HMAC keys from the DH shared secret
    byte_vec salt = c_nonce;
    salt.insert(salt.end(), s_nonce.begin(), s_nonce.end());

    if (!deriveKeys(shared_secret, c_key, s_key, c_mac, s_mac, salt))
    {
        std::cerr << "ERROR: Failed to derive session and HMAC keys" << std::endl;
        return false;
    }

    // verify KEY CONFIRMATION (HMAC)
    byte_vec to_auth;
    push_field(to_auth, s_nonce);
    push_field(to_auth, c_nonce_rec);
    push_field(to_auth, s_dh_pubkey_bin);
    push_field(to_auth, iv);
    push_field(to_auth, enc_sig);

    byte_vec hmac_calc;
    if (!computeHMAC(s_mac, to_auth, hmac_calc))
    {
        std::cerr << "ERROR: Failed to compute HMAC for key confirmation" << std::endl;
        return false;
    }

    // Enforce expected tag size and constant-time comparison
    if (hmac_calc.size() != HMAC_SIZE)
        hmac_calc.resize(HMAC_SIZE);

    if (hmac_rec.size() != HMAC_SIZE ||
        CRYPTO_memcmp(hmac_calc.data(), hmac_rec.data(), HMAC_SIZE) != 0)
    {
        std::cerr << "ERROR: HMAC verification failed (Handshake tampered)!" << std::endl;
        return false;
    }

    // decripton and verification of signature (Authentication)
    byte_vec signature;
    if (!cbcDecrypt(enc_sig, s_key, iv, signature))
        return false;

    // Server authentication and transcript verification
    byte_vec to_verify;
    push_field(to_verify, c_nonce);         // original client nonce
    push_field(to_verify, s_nonce);         // Received nonce
    push_field(to_verify, c_dh_pubkey_bin); // client DH key
    push_field(to_verify, s_dh_pubkey_bin); // Received server DH key

    EVP_MD_CTX *v_ctx = EVP_MD_CTX_new();
    if (!v_ctx)
        return false;
    int auth_ok = 0;
    if (EVP_DigestVerifyInit(v_ctx, nullptr, HASH_ALGORITHM, nullptr, s_pubkey) > 0 &&
        EVP_DigestVerifyUpdate(v_ctx, to_verify.data(), to_verify.size()) > 0)
    {
        auth_ok = EVP_DigestVerifyFinal(v_ctx, signature.data(), signature.size());
    }
    EVP_MD_CTX_free(v_ctx);

    if (auth_ok != 1)
    {
        std::cerr << "ERROR: Server authentication failed (Invalid signature)!" << std::endl;
        return false;
    }

    used_server_nonces.insert(s_nonce);

    // INFO
    std::cout << "INFO - Keys (nonce, public key) successfully received by the server." << std::endl
              << std::endl;

    // send ack to server
    // DEBUG
    // std::cout << "Sending ACK to server..." << std::endl;
    //

    // the client nonce is updated in sendToServerSecure

    // Prepare the ACK message
    byte_vec cmd_ack({'A', 'C', 'K'});
    byte_vec payload_ack; // empty payload

    // Send the ACK message over the secure channel
    if (!sendToServerSecure(sock, cmd_ack, payload_ack, c_nonce, s_nonce, c_key, c_mac, used_client_nonces))
    {
        std::cerr << "ERROR: Failed to send ACK" << std::endl;
        return false;
    }

    used_client_nonces.insert(c_nonce);

    // INFO
    std::cout << "INFO - SECURE CHANNEL CORRECTLY CREATED." << std::endl
              << std::endl;

    return true;
}

bool authenticateClient(int sock, byte_vec &c_nonce, byte_vec &s_nonce, byte_vec &c_key, byte_vec &c_mac,
                        byte_vec &s_key, byte_vec &s_mac, std::string &username, std::string &password,
                        std::set<byte_vec> &used_client_nonces, std::set<byte_vec> &used_server_nonces)
{
    std::cout << "Starting authentication process...\n";

    std::string temp_username, temp_password;

    bool auth_success = false;

    while (!auth_success)
    {
        temp_username = readInputNoSpaces("Insert username: ", 50);
        temp_password = readInputNoSpaces("Insert password: ", 128);

        // convertion in byte_vec
        byte_vec username_vec(temp_username.begin(), temp_username.end());
        byte_vec password_vec(temp_password.begin(), temp_password.end());

        // command LOGIN
        byte_vec cmd_login = toBytes("LOG");
        byte_vec auth_data;
        push_field(auth_data, username_vec);
        push_field(auth_data, password_vec);

        // sending the message
        if (!sendToServerSecure(sock, cmd_login, auth_data, c_nonce, s_nonce, c_key, c_mac, used_client_nonces))
        {
            std::cerr << "ERROR: Failed to send LOGIN message" << std::endl;
            return false;
        }
        used_client_nonces.insert(c_nonce);
        // DEBUG
        // std::cout << "DEBUG: LOGIN message sent. Waiting for server response..." << std::endl;
        // receiving server response
        byte_vec cmd_response, argument_response;
        if (!recvFromServerSecure(sock, cmd_response, argument_response, c_nonce, s_nonce, s_key, s_mac, used_server_nonces))
        {
            std::cerr << "ERROR: Failed to receive server response" << std::endl;
            return false;
        }
        used_server_nonces.insert(s_nonce);
        // check response command size
        if (cmd_response.size() != CMD_SIZE)
        {
            std::cerr << "ERROR: Invalid response command size" << std::endl;
            return false;
        }
        // check that the command is ANS
        if (cmd_response != toBytes("ANS"))
        {
            std::cerr << "ERROR: Expected ANS command, got something else" << std::endl;
            return false;
        }
        // check the argument for SUCCESS or FAIL
        std::string response_str = toString(argument_response);
        if (!strcmp(response_str.c_str(), "SUCCESS"))
        {
            std::cout << "Authentication successful." << std::endl;
            username = temp_username;
            password = temp_password;
        }
        else if (!strcmp(response_str.c_str(), "FAIL"))
        {
            std::cout << "Authentication failed." << std::endl;
            continue; // retry
        }
        // first login case
        else if (!strcmp(response_str.c_str(), "FIRST_LOGIN"))
        {
            std::cout << "First login detected. Please change your password." << std::endl;
            std::string new_password = readInputNoSpaces("Insert new password: ", 128);

            // command CNG
            byte_vec cmd_cng = toBytes("CNG");
            // send msg to server
            byte_vec cng_data;
            byte_vec new_password_vec(new_password.begin(), new_password.end());
            push_field(cng_data, new_password_vec);
            if (!sendToServerSecure(sock, cmd_cng, cng_data, c_nonce, s_nonce, c_key, c_mac, used_client_nonces))
            {
                std::cerr << "ERROR: Failed to send CNG message" << std::endl;
                return false;
            }
            used_client_nonces.insert(c_nonce);

            // receive server response
            byte_vec cmd_cng_response, argument_cng_response;
            if (!recvFromServerSecure(sock, cmd_cng_response, argument_cng_response, c_nonce, s_nonce, s_key, s_mac, used_server_nonces))
            {
                std::cerr << "ERROR: Failed to receive server response for CNG" << std::endl;
                return false;
            }
            used_server_nonces.insert(s_nonce);
            // check that the command is ANS
            if (cmd_cng_response != toBytes("ANS"))
            {
                std::cerr << "ERROR: Expected ANS command for CNG, got something else" << std::endl;
                return false;
            }
            std::string cng_response_str = toString(argument_cng_response);
            if (!strcmp(cng_response_str.c_str(), "SUCCESS"))
            {
                std::cout << "Password changed successfully." << std::endl;
            }
            else if (!strcmp(cng_response_str.c_str(), "SAME_PASSWORD"))
            {
                std::cerr << "ERROR: New password cannot be the same as the old one. Please try again." << std::endl;
                continue; // ritenta autenticazione
            }
            else
            {
                std::cerr << "ERROR: Password change failed." << std::endl;
                continue; // retry
            }
        }
        else
        {
            std::cerr << "ERROR: Unknown response argument from server" << std::endl;
            continue; // retry
        }
        // here the authentication was successful
        std::cout << "Client '" << temp_username << "' authenticated successfully." << std::endl;
        auth_success = true;
        break;
    }
    return true;
}

// function for sending encrypted and authenticated messages
bool sendToServerSecure(int sock, const byte_vec &cmd, const byte_vec &argument,
                        byte_vec &c_nonce, byte_vec &s_nonce,
                        const byte_vec &c_key, const byte_vec &c_mac,
                        std::set<byte_vec> &used_client_nonces)
{
    // create the nonce for server
    byte_vec new_c_nonce(NONCE_SIZE);
    int max_attempts = 500;
    int attempts = 0;

    // Genera un nonce che NON sia già stato usato
    do
    {
        if (RAND_bytes(new_c_nonce.data(), new_c_nonce.size()) != 1)
        {
            std::cerr << "ERROR: Failed to generate client nonce" << std::endl;
            return false;
        }
        attempts++;
        if (attempts >= max_attempts)
        {
            std::cerr << "ERROR: Failed to generate unique nonce after " << max_attempts << " attempts" << std::endl;
            return false;
        }
    } while (used_client_nonces.find(new_c_nonce) != used_client_nonces.end());

    c_nonce = new_c_nonce;

    // Compose the message to encrypt: [s_nonce][c_nonce][cmd][argument]
    byte_vec msg;
    push_field(msg, s_nonce);
    push_field(msg, c_nonce);
    push_field(msg, cmd);
    push_field(msg, argument);

    // 2. Encrypt plaintext with c_key and c_iv
    byte_vec ciphertext;
    byte_vec iv(IV_SIZE);
    if (RAND_bytes(iv.data(), iv.size()) != 1)
    {
        std::cerr << "ERROR: Failed to generate IV" << std::endl;
        return false;
    }
    if (!cbcEncrypt(msg, c_key, iv, ciphertext))
    {
        std::cerr << "ERROR: Failed to encrypt message" << std::endl;
        return false;
    }
    msg.clear();

    // Compose [IV][ciphertext] for HMAC calculation
    byte_vec to_authenticate;
    push_field(to_authenticate, iv);
    push_field(to_authenticate, ciphertext);

    // 3. Compute HMAC of ciphertext with c_mac
    byte_vec hmac(HMAC_SIZE);

    if (!computeHMAC(c_mac, to_authenticate, hmac))
    {
        std::cerr << "ERROR: Failed to compute HMAC" << std::endl;
        return false;
    }
    hmac.resize(HMAC_SIZE);

    // 4. Compose message: [IV][ciphertext][HMAC]
    msg = to_authenticate;
    push_field(msg, hmac);

    // 5. Send message using send_msg
    if (send_msg(sock, reinterpret_cast<const char *>(msg.data()), msg.size()) != (ssize_t)msg.size())
    {
        std::cerr << "ERROR: Failed to send secure message" << std::endl;
        return false;
    }

    return true;
}

// function for receiving encrypted and authenticated messages
bool recvFromServerSecure(int sock, byte_vec &cmd, byte_vec &argument,
                          byte_vec &c_nonce, byte_vec &s_nonce,
                          const byte_vec &s_key, const byte_vec &s_mac,
                          std::set<byte_vec> &used_server_nonces)
{
    // 1. Receive the message
    byte_vec buffer(BUFFER_SIZE);
    ssize_t n = recv_msg(sock, reinterpret_cast<char *>(buffer.data()), buffer.size());
    if (n <= 0)
    {
        std::cerr << "ERROR: Failed to receive secure message" << std::endl;
        return false;
    }
    buffer.resize(n);

    // 2. Extract IV, ciphertext, HMAC
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
    if (!computeHMAC(s_mac, to_authenticate, hmac_calc))
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
    if (!cbcDecrypt(ciphertext, s_key, iv, plaintext))
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
        // DEBUG
        // offset = 0;
        // if(!extract_field(s_nonce_received, plaintext, offset)){
        //     std::cerr << "ERROR: extracting s_nonce_received failed" << std::endl;
        // }
        // if(!extract_field(c_nonce_received, plaintext, offset)){
        //     std::cerr << "ERROR: extracting c_nonce_received failed" << std::endl;
        // }
        // if(!extract_field(cmd, plaintext, offset)){
        //     std::cerr << "ERROR: extracting cmd failed" << std::endl;
        // }

        return false;
    }

    // nonces control
    if (c_nonce_received != c_nonce)
    {
        std::cerr << "ERROR: Client nonce mismatch" << std::endl;
        return false;
    }

    if (used_server_nonces.find(s_nonce_received) != used_server_nonces.end())
    {
        std::cerr << "ERROR: Replay attack detected (server nonce already used in this session)" << std::endl;
        return false;
    }

    // check command size
    if (cmd.size() != CMD_SIZE)
    {
        std::cerr << "ERROR: Invalid command size (expected " << CMD_SIZE
                  << ", got " << cmd.size() << ")" << std::endl;
        return false;
    }

    // 6. Update nonce (it will be put in the used nonces set by the caller)
    s_nonce = s_nonce_received;

    return true;
}

int main()
{

    // loading the server public key from a file PEM
    EVP_PKEY *s_pubkey = loadServerPubKey(SERVER_PUB_KEY_FILE);
    if (!s_pubkey)
    {
        std::cerr << "ERROR: Failed to load server public key" << std::endl;
        return 1;
    }
    else
    {
        std::cout << "INFO - Server public key loaded successfully" << std::endl;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    // creating the socket and making the connection
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    if (connect(sock, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("connect");
        return 1;
    }
    std::cout << "Connected to the server. Write 'ext' to terminate." << std::endl;
    char buffer[1024];

    // Set to store used nonces for replay protection
    std::set<byte_vec> used_client_nonces;
    std::set<byte_vec> used_server_nonces;

    // starting the handshake in order to create the SECURE CHANNEL
    // s_pubkey: public key of the server (not DH key)
    byte_vec c_nonce, s_nonce, c_key, c_mac, s_key, s_mac;
    if (!handshakeSecureChannelClient(sock, s_pubkey, c_nonce, s_nonce, c_key, c_mac, s_key, s_mac, used_client_nonces, used_server_nonces))
    {
        std::cerr << "ERROR: Handshake failed\n";
        close(sock);
        return 1;
    }

    // used nonces sets updated in the handshake function

    // AUTHENTICATION
    std::string username, password;
    if (!authenticateClient(sock, c_nonce, s_nonce, c_key, c_mac, s_key, s_mac, username, password, used_client_nonces, used_server_nonces))
    {
        std::cerr << "ERROR: Authentication failed\n";
        close(sock);
        return 1;
    }

    // send HELP COMMAND AT THE BEGINNING
    byte_vec argument = {};
    byte_vec cmd = toBytes("HLP");
    if (!sendToServerSecure(sock, cmd, argument, c_nonce, s_nonce, c_key, c_mac, used_client_nonces))
    {
        std::cerr << "ERROR: Failed to send command to server" << std::endl;
        return 1;
    }
    used_client_nonces.insert(c_nonce);
    // receive server response
    byte_vec cmd_response = {}, argument_response = {};
    if (!recvFromServerSecure(sock, cmd_response, argument_response, c_nonce, s_nonce, s_key, s_mac, used_server_nonces))
    {
        std::cerr << "ERROR: Failed to receive server response" << std::endl;
        return 1;
    }
    used_server_nonces.insert(s_nonce);
    // check response command size
    if (cmd_response.size() != CMD_SIZE)
    {
        std::cerr << "ERROR: Invalid response command size" << std::endl;
        return 1;
    }
    // check that the command is ANS
    if (cmd_response != toBytes("ANS"))
    {
        std::cerr << "ERROR: Expected ANS command, got something else" << std::endl;
        return 1;
    }
    std::string response_str = toString(argument_response);
    std::cout << std::endl
              << response_str << std::endl
              << std::endl;

    // main loop for sending commands
    while (true)
    {
        std::string command;
        argument = {};
        cmd = {};

        command = readInputNoSpaces("Enter command: ", 10);
        if (command == "EXT" || command == "ext" || command == "Ext")
        {
            cmd = toBytes("EXT");
            // send command to server without waiting for response
            if (!sendToServerSecure(sock, cmd, argument, c_nonce, s_nonce, c_key, c_mac, used_client_nonces))
            {
                std::cerr << "ERROR: Failed to send command to server" << std::endl;
            }
            used_client_nonces.insert(c_nonce);
            break;
        }
        else if (command == "HLP" || command == "hlp" || command == "Hlp") // server does not need to be contacted
        {
            cmd = toBytes("HLP");
        }
        else if (command == "CNG" || command == "cng" || command == "Cng")
        {
            cmd = toBytes("CNG");
            std::string new_password = readInputNoSpaces("Enter new password: ", 128);

            byte_vec new_password_vec(new_password.begin(), new_password.end());
            push_field(argument, new_password_vec);
        }
        else if (command == "SGN" || command == "sgn" || command == "Sgn")
        {
            cmd = toBytes("SGN");
            std::string filename = readInputNoSpaces("Enter file name to sign: ", 255);
            byte_vec filename_vec(filename.begin(), filename.end());
            push_field(argument, filename_vec);
        }
        else if (command == "CRT" || command == "crt" || command == "Crt")
        {
            cmd = toBytes("CRT");
        }
        else if (command == "LST" || command == "lst" || command == "Lst")
        {
            cmd = toBytes("LST");
        }
        else if (command == "GET" || command == "get" || command == "Get")
        {
            cmd = toBytes("GET");
            std::string get_username = readInputNoSpaces("Enter username to get public key: ", 50);
            byte_vec get_username_vec(get_username.begin(), get_username.end());
            push_field(argument, get_username_vec);
        }
        else if (command == "VRF" || command == "vrf" || command == "Vrf")
        {
            cmd = toBytes("VRF");
            std::string filename = readInputNoSpaces("Enter file name to verify signature: ", 255);
            byte_vec filename_vec(filename.begin(), filename.end());

            std::string signer_username = readInputNoSpaces("Enter the signer username: ", 50);
            byte_vec signer_username_vec(signer_username.begin(), signer_username.end());

            std::cout << "Enter signature (hex): ";
            std::string signature_hex;
            std::getline(std::cin, signature_hex);
            // removing spaces from hex signature (allowed for readability)
            signature_hex.erase(std::remove_if(signature_hex.begin(), signature_hex.end(), ::isspace), signature_hex.end());
            byte_vec signature_vec(fromHex(signature_hex));

            push_field(argument, filename_vec);
            push_field(argument, signer_username_vec);
            push_field(argument, signature_vec);
        }
        else if (command == "DEL" || command == "del" || command == "Del")
        {
            cmd = toBytes("DEL");
        }
        else
        {
            std::cout << std::endl
                      << "Unknown command. Type \'HLP\' to see available commands." << std::endl
                      << std::endl;
            continue;
        }
        // send command to server and receive response
        if (!sendToServerSecure(sock, cmd, argument, c_nonce, s_nonce, c_key, c_mac, used_client_nonces))
        {
            std::cerr << "ERROR: Failed to send command to server" << std::endl;
            break;
        }
        used_client_nonces.insert(c_nonce);
        cmd_response = {}, argument_response = {};
        if (!recvFromServerSecure(sock, cmd_response, argument_response, c_nonce, s_nonce, s_key, s_mac, used_server_nonces))
        {
            std::cerr << "ERROR: Failed to receive server response" << std::endl;
            break;
        }
        used_server_nonces.insert(s_nonce);
        // check that the command is ANS
        if (cmd_response != toBytes("ANS"))
        {
            std::cerr << "ERROR: Expected ANS command, got something else" << std::endl;
            break;
        }
        std::string response_str = toString(argument_response);
        std::cout << std::endl
                  << "---SERVER RESPONSE--- \n\n"
                  << response_str << std::endl
                  << "---------------------"
                  << std::endl
                  << std::endl;
    }

    EVP_PKEY_free(s_pubkey);
    close(sock);
    return 0;
}
