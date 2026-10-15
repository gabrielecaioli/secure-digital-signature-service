#pragma once
#include <cstddef>          // For size_t type used in function parameters
#include <cstdint>          // For uint32_t type used in U32_SIZE macro
#include <unistd.h>         // For ssize_t type used in recv_msg/send_msg return types
#include <vector>           // For std::vector and byte_vec type alias
#include <openssl/evp.h>    // For EVP_PKEY, EVP_sha256() and cryptographic operations
#include <string>           // For std::string type used in toBytes/toString/fromHex functions
#include <openssl/rand.h>   // For RAND_bytes (secure random number generation)
#include <openssl/crypto.h>  // For CRYPTO_memcmp (constant-time memory comparison)
#include <set>           // For std::set used in nonce tracking 

// ============ DIMENSIONS ============
#define CMD_SIZE 3
#define IV_SIZE 16
#define NONCE_SIZE 16
#define HMAC_SIZE 32
#define BUFFER_SIZE 4096
#define U32_SIZE sizeof(uint32_t)

// ============ CRYPTOGRAPHY ============
#define AES_KEY_SIZE 32              // AES-256 key size (32 bytes)
#define RSA_KEY_BITS 2048            // RSA key size in bits
#define RSA_SIGNATURE_SIZE 256       // RSA-2048 signature size (256 bytes)
#define DH_GROUP "ffdhe2048"         // Diffie-Hellman group
#define HASH_ALGORITHM EVP_sha256()  // Hash algorithm (SHA-256)
#define HASH_SIZE 32                 // SHA-256 output size (32 bytes)
#define HASH_NAME "SHA256"           // Hash algorithm name for HMAC/signature

// ============ KEY DERIVATION ============
#define DERIVED_KEY_SIZE 32          // Size of each derived key (c_key, s_key, c_mac, s_mac)
#define TOTAL_DERIVED_SIZE (4 * DERIVED_KEY_SIZE) // Total HKDF output size

// ============ DATABASE ============
#define SALT_SIZE 16                 // Salt size for password hashing
#define CSV_COLUMNS 7            // Minimum number of columns in employees.csv

// ============ NETWORK ============
#define SERVER_PORT 4444             // Server listening port
#define SERVER_BACKLOG 5             // Maximum pending connections
#define SERVER_IP "127.0.0.1"        // Server IP address (localhost)

// ============ SHARED FILE PATH ============
#define SERVER_PUB_KEY_FILE "keys/server_pub.pem"    // Server public key file

// Type alias for byte vector
using byte_vec = std::vector<unsigned char>;

// returns -1 on error, otherwise the length of the received message
ssize_t recv_msg(int sock, char* buffer, size_t bufsize);

// returns -1 on error, otherwise the length of the sent message
ssize_t send_msg(int sock, const char* buffer, size_t msglen);

// function for generating a couple of DH keys
bool generate_dh_keys(EVP_PKEY **dhKeysPair);

// extracting the public key from the DH key pair
bool extract_dh_public_key_der(EVP_PKEY *dhKeysPair, std::vector<unsigned char> &publicKey);

// generating the DH shared key
bool generate_dh_shared_key(EVP_PKEY* our_keypair, const std::vector<unsigned char>& peer_pubkey_der, std::vector<unsigned char>& shared_key);

// function that derives session keys and HMAC from the DH shared secret
bool deriveKeys(const byte_vec& shared_key, byte_vec& c_key, byte_vec& s_key, byte_vec& c_mac, byte_vec& s_mac, const byte_vec& salt);

// function for encrypting data AES-256-CBC
bool cbcEncrypt(const byte_vec& plaintext, const byte_vec& key, const byte_vec& iv, byte_vec& ciphertext);

// function for decrypting data AES-256-CBC
bool cbcDecrypt(const byte_vec& ciphertext, const byte_vec& key, const byte_vec& iv, byte_vec& plaintext);

// function for computing the hmac of a message
bool computeHMAC(const byte_vec& key, const byte_vec& data, byte_vec& hmac);

// helper function to push a field with its length prefix
void push_field(byte_vec &dst, const byte_vec &field);

// utility function for extracting length-prefixed fields from a buffer
bool extract_field(byte_vec& field, const byte_vec& buffer, size_t& offset);

// Convert std::string -> byte_vec
byte_vec toBytes(const std::string& s);

// Convert byte_vec -> std::string
std::string toString(const byte_vec& v);

// converts hexadecimal string to byte_vec
byte_vec fromHex(const std::string &hex);
