#include "utility.h"

// Network operations
#include <arpa/inet.h>           // For htonl, ntohl (endianness conversion) and socket operations

// String and memory manipulation
#include <cstring>               // For memcpy used in extract_field
#include <iostream>              // For std::cout, std::cerr (error logging)
#include <sstream>               // For std::stringstream used in fromHex

// OpenSSL cryptographic operations
#include <openssl/hmac.h>        // For HMAC message authentication (computeHMAC)
#include <openssl/kdf.h>         // For HKDF key derivation (deriveKeys)
#include <openssl/param_build.h> // For building DH parameters (generate_dh_keys)
#include <openssl/core_names.h>  // For OpenSSL parameter name constants (OSSL_PKEY_PARAM_GROUP_NAME)
#include <openssl/encoder.h>     // For encoding keys to DER format (extract_dh_public_key_der)
#include <openssl/params.h>      // For advanced OpenSSL parameter handling (generate_dh_keys)
#include <openssl/x509.h>        // For d2i_PUBKEY used in generate_dh_shared_key

// function for receiving messages (length then data)
ssize_t recv_msg(int sock, char *buffer, size_t bufsize)
{
    uint32_t msg_len_net;
    ssize_t n = read(sock, &msg_len_net, sizeof(msg_len_net));
    if (n == 0)
        return 0; // connection closed
    if (n != sizeof(msg_len_net))
        return -1;
    uint32_t msg_len = ntohl(msg_len_net);
    if (msg_len > bufsize)
        return -1; // buffer too small
    ssize_t received = 0;
    while (received < (ssize_t)msg_len)
    {
        ssize_t r = read(sock, buffer + received, msg_len - received);
        if (r <= 0)
            return -1;
        received += r;
    }
    return received;
}

// function for sending messages (length then data)
ssize_t send_msg(int sock, const char *buffer, size_t msglen)
{
    uint32_t len_net = htonl(msglen);
    ssize_t n = write(sock, &len_net, sizeof(len_net));
    if (n != sizeof(len_net))
        return -1;
    ssize_t sent = 0;
    while (sent < (ssize_t)msglen)
    {
        ssize_t s = write(sock, buffer + sent, msglen - sent);
        if (s <= 0)
            return -1;
        sent += s;
    }
    return sent;
}

// function for generating a couple of DH keys
bool generate_dh_keys(EVP_PKEY **dhKeysPair)
{
    if (!dhKeysPair)
        return false;
    bool ok = false;
    EVP_PKEY_CTX *param_ctx = nullptr;
    EVP_PKEY *params = nullptr;
    EVP_PKEY_CTX *key_ctx = nullptr;
    // Build DH parameters for group "ffdhe2048"
    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld)
        return false;
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, DH_GROUP, 0))
    {
        OSSL_PARAM_BLD_free(param_bld);
        return false;
    }
    OSSL_PARAM *params_os = OSSL_PARAM_BLD_to_param(param_bld);
    OSSL_PARAM_BLD_free(param_bld);
    if (!params_os)
        return false;

    param_ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!param_ctx)
    {
        OSSL_PARAM_free(params_os);
        return false;
    }

    if (EVP_PKEY_paramgen_init(param_ctx) <= 0)
    {
        EVP_PKEY_CTX_free(param_ctx);
        OSSL_PARAM_free(params_os);
        return false;
    }

    if (EVP_PKEY_CTX_set_params(param_ctx, params_os) <= 0)
    {
        EVP_PKEY_CTX_free(param_ctx);
        OSSL_PARAM_free(params_os);
        return false;
    }

    if (EVP_PKEY_paramgen(param_ctx, &params) <= 0)
    {
        EVP_PKEY_CTX_free(param_ctx);
        OSSL_PARAM_free(params_os);
        return false;
    }

    EVP_PKEY_CTX_free(param_ctx);
    OSSL_PARAM_free(params_os);

    // Generate DH key pair
    key_ctx = EVP_PKEY_CTX_new(params, NULL);
    if (!key_ctx)
    {
        EVP_PKEY_free(params);
        return false;
    }

    if (EVP_PKEY_keygen_init(key_ctx) <= 0)
    {
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(key_ctx);
        return false;
    }

    if (EVP_PKEY_keygen(key_ctx, dhKeysPair) <= 0)
    {
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(key_ctx);
        return false;
    }

    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(key_ctx);
    return true;
}

// extracting the public key from the DH key pair
bool extract_dh_public_key_der(EVP_PKEY *dhKeysPair, std::vector<unsigned char> &publicKey)
{
    if (!dhKeysPair)
        return false;

    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(dhKeysPair, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", NULL);
    if (!ectx)
        return false;

    unsigned char *buf = nullptr;
    size_t len = 0;
    int err = !OSSL_ENCODER_to_data(ectx, &buf, &len);
    OSSL_ENCODER_CTX_free(ectx);

    if (err || !buf || len == 0)
    {
        if (buf)
            OPENSSL_free(buf);
        return false;
    }

    publicKey.assign(buf, buf + len);
    OPENSSL_free(buf);
    return true;
}

// function for generating the DH shared key
bool generate_dh_shared_key(EVP_PKEY *our_keypair, const byte_vec &peer_pubkey_der, byte_vec &shared_key)
{
    if (!our_keypair || peer_pubkey_der.empty())
        return false;

    // Decode the peer's public key from DER to EVP_PKEY*
    const unsigned char *p = peer_pubkey_der.data();
    EVP_PKEY *peer_pubkey = d2i_PUBKEY(NULL, &p, peer_pubkey_der.size());
    if (!peer_pubkey)
        return false;

    // Create the context for key derivation
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_keypair, NULL);
    if (!ctx)
    {
        EVP_PKEY_free(peer_pubkey);
        return false;
    }

    // Initialize derivation and set the peer's public key
    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Determine the length of the shared key
    size_t keylen = 0;
    if (EVP_PKEY_derive(ctx, NULL, &keylen) <= 0)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Derive the shared key
    shared_key.resize(keylen);
    if (EVP_PKEY_derive(ctx, shared_key.data(), &keylen) <= 0)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    shared_key.resize(keylen);

    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_CTX_free(ctx);
    return true;
}

// function that derives session keys and HMAC from the DH shared secret
bool deriveKeys(const byte_vec &shared_key, byte_vec &c_key, byte_vec &s_key, byte_vec &c_mac, byte_vec &s_mac, const byte_vec &salt)
{
    const size_t TOTAL_LEN = 4 * DERIVED_KEY_SIZE;
    byte_vec okm(TOTAL_LEN);
    size_t okm_len = TOTAL_LEN;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx)
        return false;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, HASH_ALGORITHM) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_key.data(), shared_key.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, nullptr, 0) <= 0 ||
        EVP_PKEY_derive(pctx, okm.data(), &okm_len) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    c_key.assign(okm.begin(), okm.begin() + DERIVED_KEY_SIZE);
    s_key.assign(okm.begin() + DERIVED_KEY_SIZE, okm.begin() + 2 * DERIVED_KEY_SIZE);
    c_mac.assign(okm.begin() + 2 * DERIVED_KEY_SIZE, okm.begin() + 3 * DERIVED_KEY_SIZE);
    s_mac.assign(okm.begin() + 3 * DERIVED_KEY_SIZE, okm.end());

    return true;
}

// function for encrypting data AES-256-CBC
bool cbcEncrypt(const byte_vec &plaintext, const byte_vec &key, const byte_vec &iv, byte_vec &ciphertext)
{
    if (key.size() != AES_KEY_SIZE || iv.size() != IV_SIZE)
        return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// function for decrypting data AES-256-CBC
bool cbcDecrypt(const byte_vec &ciphertext, const byte_vec &key, const byte_vec &iv, byte_vec &plaintext)
{
    if (key.size() != AES_KEY_SIZE || iv.size() != IV_SIZE)
        return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext.resize(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Compute the HMAC of a message using the new OpenSSL 3.x EVP_MAC API (HMAC-SHA256)
bool computeHMAC(const byte_vec &key, const byte_vec &data, byte_vec &hmac)
{
    EVP_MAC *mac = nullptr;
    EVP_MAC_CTX *ctx = nullptr;
    bool result = false;
    size_t out_len = 0;

    mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac)
        return false;

    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx)
    {
        EVP_MAC_free(mac);
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>(HASH_NAME), 0),
        OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx, key.data(), key.size(), params) != 1)
    {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    if (EVP_MAC_update(ctx, data.data(), data.size()) != 1)
    {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    size_t mac_len = 0;
    if (EVP_MAC_final(ctx, nullptr, &mac_len, 0) != 1)
    {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    hmac.resize(mac_len);
    if (EVP_MAC_final(ctx, hmac.data(), &out_len, mac_len) != 1)
    {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return false;
    }

    hmac.resize(out_len);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return true;
}

// helper function to push a field with its length prefix
void push_field(byte_vec &dst, const byte_vec &field)
{
    uint32_t len = htonl(field.size());
    dst.insert(dst.end(),
               reinterpret_cast<unsigned char *>(&len),
               reinterpret_cast<unsigned char *>(&len) + sizeof(len));
    dst.insert(dst.end(), field.begin(), field.end());
}

// utility function for extracting length-prefixed fields from a buffer
bool extract_field(byte_vec &field, const byte_vec &buffer, size_t &offset)
{
    if (offset + U32_SIZE > buffer.size())
    {
        return false;
    }
    uint32_t len;
    memcpy(&len, buffer.data() + offset, U32_SIZE);
    len = ntohl(len);
    offset += U32_SIZE;

    if (offset + len > buffer.size())
    {
        // INFO-ERROR
        std::cerr << "ERROR: extract_field: OVERFLOW (need=" << (offset + len)
                  << ", have=" << buffer.size() << ")" << std::endl;
        return false;
    }
    field.assign(buffer.begin() + offset, buffer.begin() + offset + len);
    offset += len;
    return true;
}

// Convert std::string -> byte_vec
byte_vec toBytes(const std::string &s)
{
    return byte_vec(s.begin(), s.end());
}

// Convert byte_vec -> std::string
std::string toString(const byte_vec &v)
{
    return std::string(v.begin(), v.end());
}

// convert hexadecimal string to byte_vec
byte_vec fromHex(const std::string &hex)
{
    byte_vec out;
    if (hex.size() % 2 != 0)
        return {};
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        if (!(ss >> byte))
            return {};
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}
