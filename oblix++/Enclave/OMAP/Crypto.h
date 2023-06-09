#include <sgx_tcrypto.h>
#include "sgxaes.h"

#ifndef CRYPTO_H
#define CRYPTO_H

#include "Node.h"
#include <array>
#include <cstdint>

using EncBucketBytes = std::array<byte_t, sizeof (Node) * Z + SGX_AESGCM_IV_SIZE >;

//extern const char *key_str;
extern sgx_aes_gcm_128bit_key_t key_data;
extern sgx_aes_gcm_128bit_key_t *key;

extern KeySchedule *ks;

extern const sgx_ec256_public_t g_sp_pub_key;

unsigned __int128 ctrFromBytes(std::array<uint8_t, SGX_AESGCM_IV_SIZE> bytes);

void ctrToBytes(uint8_t *res, unsigned __int128 x);

std::array<uint8_t, SGX_AESGCM_IV_SIZE> ctrToBytes(unsigned __int128 x);

void generateIV(uint8_t *output, int i);

// encrypt() and decrypt() should be called from enclave code only

// encrypt using a global key
// TODO: fix this; should use key obtained from client
void encrypt(uint8_t *plaintext, uint32_t plaintext_length, uint8_t *ciphertext, int i);

void decrypt(const uint8_t *ciphertext, uint32_t ciphertext_length, uint8_t *plaintext);

void encrypt_with_aad(uint8_t *plaintext, uint32_t plaintext_length,
        uint8_t *ciphertext,
        uint8_t *aad, uint32_t aad_len);

void decrypt_with_aad(const uint8_t *ciphertext, uint32_t ciphertext_length,
        uint8_t *plaintext,
        uint8_t *aad, uint32_t aad_len);

uint32_t enc_size(uint32_t plaintext_size);
uint32_t dec_size(uint32_t ciphertext_size);

void test_big_encrypt();
void test_small_encrypts();


// this class provides support for stream encrypting
// [ciphertext length][ciphertext IV][ciphertext MAC][ciphertext]

class StreamCipher {
public:
    StreamCipher(uint8_t *ciphertext_ptr);

    ~StreamCipher();

    void encrypt(uint8_t *plaintext, uint32_t size);

    void reset(uint8_t *new_ciphertext_ptr);

    void finish();

    uint32_t bytes_written();

    uint32_t ciphertext_size;

    uint8_t *iv_ptr;
    uint8_t *mac_ptr;

    uint8_t *cipher_ptr;
    uint8_t *current_cipher_ptr;
    uint8_t leftover_plaintext[AES_BLOCK_SIZE];
    uint32_t leftover_plaintext_size;

    AesGcm *cipher;
};


// Given a ciphertext, stream decipher into different plaintext
// [ciphertext length][ciphertext IV][ciphertext MAC][ciphertext]
// no bounds checking

class StreamDecipher {
public:
    StreamDecipher(uint8_t *ciphertext_ptr, uint32_t enc_size);

    ~StreamDecipher();

    void decrypt(uint8_t *plaintext_ptr, uint32_t size);

    void reset(uint8_t *new_ciphertext_ptr, uint32_t enc_size);

    uint8_t *iv_ptr;
    uint8_t *mac_ptr;

    uint8_t *cipher_ptr;
    uint8_t *current_cipher_ptr;
    uint8_t leftover_plaintext[AES_BLOCK_SIZE];
    uint8_t *leftover_plaintext_ptr;
    uint32_t leftover_plaintext_size;

    AesGcm *cipher;
    uint32_t total_cipher_size;
};

class MAC {
public:

    MAC() {
        //uint8_t iv[SGX_AESGCM_IV_SIZE+1] = "000000000000";
        //cipher = new AesGcm(ks, iv, SGX_AESGCM_IV_SIZE);
    }

    ~MAC() {
        //delete cipher;
    }

    void mac(uint8_t *ptr, uint32_t len);

    //AesGcm *cipher;
};





// Encryption constants (in bytes)

constexpr int IV = SGX_AESGCM_IV_SIZE;
constexpr int AESKey = 16;

/*
 * Performs encryption using AES-256-CBC
 * and provides various helper functions
 */
class Crypto {
public:
    static void Setup();
    static void Cleanup();
    static EncBucketBytes Encrypt(bytes<AESKey> key, BucketBytes b, size_t clen_size, size_t plaintext_size, int i);
    static BucketBytes Decrypt(bytes<AESKey> key, EncBucketBytes b, size_t clen_size);
    static int GetCiphertextLength(int plen);
    static void refreshIV(int n);


};

#endif