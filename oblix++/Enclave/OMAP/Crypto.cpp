#include "Crypto.h"

#include <sgx_trts.h>

//#include "common.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string> 

sgx_aes_gcm_128bit_key_t key_data = {0};
sgx_aes_gcm_128bit_key_t *key = &key_data;
const KeySchedule ks_backup = KeySchedule((unsigned char *) key_data, SGX_AESGCM_KEY_SIZE);
KeySchedule *ks = (KeySchedule *) & ks_backup;

std::array<uint8_t, SGX_AESGCM_IV_SIZE> localiv{0};
unsigned __int128 ctr = 0;

void initKeySchedule() {
    if (ks == NULL) {
        //print_hex(key_data, 16);
        ks = new KeySchedule((unsigned char *) key_data, SGX_AESGCM_KEY_SIZE);
    }
}

void gcKeySchedule() {
    delete ks;
}

unsigned __int128 ctrFromBytes(std::array<uint8_t, SGX_AESGCM_IV_SIZE> bytes) {
    unsigned __int128 x = 0;
    x += (bytes[0] << 88);
    x += (bytes[1] << 80);
    x += (bytes[2] << 72);
    x += (bytes[3] << 64);
    x += (bytes[4] << 56);
    x += (bytes[5] << 48);
    x += (bytes[6] << 40);
    x += (bytes[7] << 32);
    x += (bytes[8] << 24);
    x += (bytes[9] << 16);
    x += (bytes[10] << 8);
    x += (bytes[11] << 0);
    return x;
}

void ctrToBytes(uint8_t *res, unsigned __int128 x) {
    res[0] = (x >> 88);
    res[1] = (x >> 80);
    res[2] = (x >> 72);
    res[3] = (x >> 64);
    res[4] = (x >> 56);
    res[5] = (x >> 48);
    res[6] = (x >> 40);
    res[7] = (x >> 32);
    res[8] = (x >> 24);
    res[9] = (x >> 16);
    res[10] = (x >> 8);
    res[11] = (x >> 0);
}

std::array<uint8_t, SGX_AESGCM_IV_SIZE> ctrToBytes(unsigned __int128 x) {
    std::array<uint8_t, SGX_AESGCM_IV_SIZE> res;
    res[0] = (x >> 88);
    res[1] = (x >> 80);
    res[2] = (x >> 72);
    res[3] = (x >> 64);
    res[4] = (x >> 56);
    res[5] = (x >> 48);
    res[6] = (x >> 40);
    res[7] = (x >> 32);
    res[8] = (x >> 24);
    res[9] = (x >> 16);
    res[10] = (x >> 8);
    res[11] = (x >> 0);
    return res;
}

void generateIV(uint8_t *output, int i) {
    ctrToBytes(output, ctr + i);
}
// encrypt() and decrypt() should be called from enclave code only
// TODO: encrypt() and decrypt() should return status

// encrypt using a global key
// TODO: fix this; should use key obtained from client

void encrypt(uint8_t *plaintext, uint32_t plaintext_length,
        uint8_t *ciphertext, int i) {

    initKeySchedule();

    // key size is 12 bytes/128 bits
    // IV size is 12 bytes/96 bits
    // MAC size is 16 bytes/128 bits

    // one buffer to store IV (12 bytes) + ciphertext + mac (16 bytes)

    uint8_t *iv_ptr = ciphertext;
    // generate random IV
    generateIV(iv_ptr, i);
    //sgx_read_rand(iv_ptr, SGX_AESGCM_IV_SIZE);
    //  sgx_aes_gcm_128bit_tag_t *mac_ptr = (sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE);
    uint8_t *ciphertext_ptr = ciphertext + SGX_AESGCM_IV_SIZE;
    //  uint8_t *ciphertext_ptr = ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;

    AesGcm cipher(ks, iv_ptr, SGX_AESGCM_IV_SIZE);
    cipher.encrypt(plaintext, plaintext_length, ciphertext_ptr, plaintext_length);
    //  memcpy(mac_ptr, cipher.tag().t, SGX_AESGCM_MAC_SIZE);

}

void decrypt(const uint8_t *ciphertext, uint32_t ciphertext_length,
        uint8_t *plaintext) {

    initKeySchedule();

    // decrypt using a global key
    // TODO: fix this; should use key obtained from client

    // key size is 12 bytes/128 bits
    // IV size is 12 bytes/96 bits
    // MAC size is 16 bytes/128 bits

    // one buffer to store IV (12 bytes) + ciphertext + mac (16 bytes)

    uint32_t plaintext_length = ciphertext_length - SGX_AESGCM_IV_SIZE;
    //  uint32_t plaintext_length = ciphertext_length - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

    uint8_t *iv_ptr = (uint8_t *) ciphertext;
    sgx_aes_gcm_128bit_tag_t *mac_ptr = (sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE);
    uint8_t *ciphertext_ptr = (uint8_t *) (ciphertext + SGX_AESGCM_IV_SIZE);
    //  uint8_t *ciphertext_ptr = (uint8_t *) (ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);

    AesGcm decipher(ks, iv_ptr, SGX_AESGCM_IV_SIZE);
    decipher.decrypt(ciphertext_ptr, plaintext_length, plaintext, plaintext_length);
    //  if (memcmp(mac_ptr, decipher.tag().t, SGX_AESGCM_MAC_SIZE) != 0) {
    //    //printf("Decrypt: invalid mac\n");
    //  }
}

void encrypt_with_aad(uint8_t *plaintext, uint32_t plaintext_length,
        uint8_t *ciphertext,
        uint8_t *aad, uint32_t aad_len) {

    initKeySchedule();

    // key size is 12 bytes/128 bits
    // IV size is 12 bytes/96 bits
    // MAC size is 16 bytes/128 bits

    // one buffer to store IV (12 bytes) + ciphertext + mac (16 bytes)

    uint8_t *iv_ptr = ciphertext;
    // generate random IV
    sgx_read_rand(iv_ptr, SGX_AESGCM_IV_SIZE);
    sgx_aes_gcm_128bit_tag_t *mac_ptr = (sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE);
    uint8_t *ciphertext_ptr = ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;

    AesGcm cipher(ks, iv_ptr, SGX_AESGCM_IV_SIZE);
    cipher.aad((unsigned char *) aad, (size_t) aad_len);
    cipher.encrypt(plaintext, plaintext_length, ciphertext_ptr, plaintext_length);
    memcpy(mac_ptr, cipher.tag().t, SGX_AESGCM_MAC_SIZE);

}

void decrypt_with_aad(const uint8_t *ciphertext, uint32_t ciphertext_length,
        uint8_t *plaintext,
        uint8_t *aad, uint32_t aad_len) {

    initKeySchedule();

    // decrypt using a global key
    // TODO: fix this; should use key obtained from client

    // key size is 12 bytes/128 bits
    // IV size is 12 bytes/96 bits
    // MAC size is 16 bytes/128 bits

    // one buffer to store IV (12 bytes) + ciphertext + mac (16 bytes)

    uint32_t plaintext_length = ciphertext_length - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

    uint8_t *iv_ptr = (uint8_t *) ciphertext;
    sgx_aes_gcm_128bit_tag_t *mac_ptr = (sgx_aes_gcm_128bit_tag_t *) (ciphertext + SGX_AESGCM_IV_SIZE);
    uint8_t *ciphertext_ptr = (uint8_t *) (ciphertext + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);

    AesGcm decipher(ks, iv_ptr, SGX_AESGCM_IV_SIZE);
    decipher.aad((unsigned char *) aad, (size_t) aad_len);
    decipher.decrypt(ciphertext_ptr, plaintext_length, plaintext, plaintext_length);
    if (memcmp(mac_ptr, decipher.tag().t, SGX_AESGCM_MAC_SIZE) != 0) {
        //    printf("Decrypt: invalid mac\n");
    }
}

uint32_t enc_size(uint32_t plaintext_size) {
    return plaintext_size + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
}

uint32_t dec_size(uint32_t ciphertext_size) {
    return ciphertext_size - (SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
}

StreamCipher::StreamCipher(uint8_t *ciphertext_ptr) {
    cipher = NULL;
    reset(ciphertext_ptr);
}

StreamCipher::~StreamCipher() {
    delete cipher;
}

void StreamCipher::reset(uint8_t *new_ciphertext_ptr) {

    initKeySchedule();

    iv_ptr = new_ciphertext_ptr;
    mac_ptr = new_ciphertext_ptr + SGX_AESGCM_IV_SIZE;
    cipher_ptr = new_ciphertext_ptr + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    current_cipher_ptr = cipher_ptr;

    sgx_read_rand(iv_ptr, SGX_AESGCM_IV_SIZE);

    if (cipher != NULL) {
        delete cipher;
    }

    cipher = new AesGcm(ks, iv_ptr, SGX_AESGCM_IV_SIZE);
    leftover_plaintext_size = 0;
}

void StreamCipher::encrypt(uint8_t *plaintext, uint32_t size) {

    initKeySchedule();

    uint32_t merge_bytes = 0;
    uint32_t copy_bytes = 0;
    (void) merge_bytes;

    // simply copy to buffer if there isn't enough to encrypt
    if (leftover_plaintext_size + size < AES_BLOCK_SIZE) {
        memcpy(leftover_plaintext + leftover_plaintext_size, plaintext, copy_bytes);
        leftover_plaintext_size += size;
        return;
    }

    // otherwise, there must be enough bytes to at least encrypt a single AES block
    copy_bytes = AES_BLOCK_SIZE - leftover_plaintext_size;
    memcpy(leftover_plaintext + leftover_plaintext_size, plaintext, copy_bytes);
    // go ahead and encrypt
    cipher->encrypt(leftover_plaintext, AES_BLOCK_SIZE, current_cipher_ptr, AES_BLOCK_SIZE);
    current_cipher_ptr += AES_BLOCK_SIZE;

    leftover_plaintext_size = 0;

    // otherwise, encrypt in blocks
    uint32_t new_leftover_size = (size - copy_bytes) % AES_BLOCK_SIZE;
    uint32_t stream_enc_size = (size - copy_bytes) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;

    if (stream_enc_size > 0) {
        cipher->encrypt(plaintext + copy_bytes, stream_enc_size, current_cipher_ptr, stream_enc_size);
        current_cipher_ptr += stream_enc_size;
    }

    // copy leftover size to leftover_plaintext
    if (new_leftover_size > 0) {
        memcpy(leftover_plaintext, plaintext + copy_bytes + stream_enc_size, new_leftover_size);
        leftover_plaintext_size = new_leftover_size;
    }

}

void StreamCipher::finish() {
    if (leftover_plaintext_size > 0) {
        cipher->encrypt(leftover_plaintext, leftover_plaintext_size, current_cipher_ptr, leftover_plaintext_size);
        current_cipher_ptr += leftover_plaintext_size;
    }

    // also need to copy over the final MAC
    memcpy(mac_ptr, cipher->tag().t, SGX_AESGCM_MAC_SIZE);

    //*( (uint32_t *) (iv_ptr - 4)) = (current_cipher_ptr - cipher_ptr + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
}

uint32_t StreamCipher::bytes_written() {
    return current_cipher_ptr - iv_ptr;
}

StreamDecipher::StreamDecipher(uint8_t *ciphertext_ptr, uint32_t enc_size) {
    cipher = NULL;
    reset(ciphertext_ptr, enc_size);
}

StreamDecipher::~StreamDecipher() {
    delete cipher;
}

void StreamDecipher::reset(uint8_t *new_ciphertext_ptr, uint32_t enc_size) {

    initKeySchedule();

    this->total_cipher_size = enc_size - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE;

    iv_ptr = new_ciphertext_ptr;
    mac_ptr = new_ciphertext_ptr + SGX_AESGCM_IV_SIZE;
    cipher_ptr = new_ciphertext_ptr + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE;
    current_cipher_ptr = cipher_ptr;

    if (cipher != NULL) {
        delete cipher;
    }
    cipher = new AesGcm(ks, iv_ptr, SGX_AESGCM_IV_SIZE);

    leftover_plaintext_size = 0;
    leftover_plaintext_ptr = leftover_plaintext;
}

void StreamDecipher::decrypt(uint8_t *plaintext_ptr, uint32_t size) {

    uint32_t copied_bytes = 0;

    if (leftover_plaintext_size >= size) {
        memcpy(plaintext_ptr, leftover_plaintext_ptr, size);
        leftover_plaintext_ptr += size;
        leftover_plaintext_size -= size;
        return;
    }

    // if there are bytes left over from leftover_plaintext, copy that first
    if (leftover_plaintext_size > 0) {
        memcpy(plaintext_ptr, leftover_plaintext_ptr, leftover_plaintext_size);
        copied_bytes = leftover_plaintext_size;
    }

    leftover_plaintext_ptr = leftover_plaintext;
    leftover_plaintext_size = 0;

    // decrypt (size - copied_bytes), up to AES_BLOCK_SIZE
    uint32_t decrypt_bytes = (size - copied_bytes) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    if (decrypt_bytes > 0) {
        cipher->decrypt(current_cipher_ptr, decrypt_bytes, plaintext_ptr + copied_bytes, decrypt_bytes);
        current_cipher_ptr += decrypt_bytes;
    }

    uint32_t final_size = (size - copied_bytes) % AES_BLOCK_SIZE;
    total_cipher_size = total_cipher_size - copied_bytes - decrypt_bytes;

    // printf("[StreamDecipher::decrypt] size is %u, leftover_plaintext_size is %u, decrypt_bytes is %u, copied_bytes is %u, final_size is %u, total_cipher_size is %u\n",
    // 		 size,
    // 		 leftover_plaintext_size,
    // 		 decrypt_bytes,
    // 		 copied_bytes,
    // 		 final_size,
    // 		 total_cipher_size);

    if (total_cipher_size > AES_BLOCK_SIZE) {
        // decrypt AES_BLOCK_SIZE into leftover_plaintext
        cipher->decrypt(current_cipher_ptr, AES_BLOCK_SIZE, leftover_plaintext, AES_BLOCK_SIZE);
        leftover_plaintext_size = AES_BLOCK_SIZE;
        current_cipher_ptr += AES_BLOCK_SIZE;
    } else {
        // decrypt all the rest of the bytes into leftover_plaintext
        cipher->decrypt(current_cipher_ptr, total_cipher_size, leftover_plaintext, total_cipher_size);
        leftover_plaintext_size = total_cipher_size;
        current_cipher_ptr += total_cipher_size;
    }

    // printf("[StreamDecipher::decrypt] size is %u, leftover_plaintext_size is %u, decrypt_bytes is %u, copied_bytes is %u, final_size is %u, total_cipher_size is %u\n",
    // 		 size,
    // 		 leftover_plaintext_size,
    // 		 decrypt_bytes,
    // 		 copied_bytes,
    // 		 final_size,
    // 		 total_cipher_size);


    //uint32_t *test_ptr = (uint32_t *) leftover_plaintext_ptr;
    //printf("test_ptr is %u\n", *test_ptr);

    // copy final_size 
    memcpy(plaintext_ptr + copied_bytes + decrypt_bytes, leftover_plaintext_ptr, final_size);
    leftover_plaintext_ptr += final_size;
    leftover_plaintext_size -= final_size;
}

void MAC::mac(uint8_t *mac_ptr, uint32_t len) {
    (void) mac_ptr;
    (void) len;
    // cipher->aad((unsigned char *) mac_ptr, len);
}

void Crypto::Setup() {
    initKeySchedule();
}

void Crypto::Cleanup() {
}

static void error(const char *msg) {
    throw msg;
}

EncBucketBytes Crypto::Encrypt(bytes<AESKey> key, BucketBytes plaintext, size_t clen_size, size_t plaintext_size, int i) {
    EncBucketBytes ciphertext;
    encrypt((uint8_t*) plaintext.data(), plaintext_size, ciphertext.data(), i);
    return ciphertext;
}

BucketBytes Crypto::Decrypt(bytes<AESKey> key, EncBucketBytes ciphertext, size_t clen_size) {
    BucketBytes plaintext;
    decrypt((uint8_t*) ciphertext.data(), clen_size, plaintext.data());

    return plaintext;
}

int Crypto::GetCiphertextLength(int plen) {
    return plen + SGX_AESGCM_IV_SIZE;
}

void Crypto::refreshIV(int n) {
    ctr = ctrFromBytes(localiv);
    localiv = ctrToBytes(ctr + n);
}