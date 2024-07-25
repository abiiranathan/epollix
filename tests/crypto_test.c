#include "../include/crypto.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_crypto_init_cleanup(void) {
    crypto_init();
}

void test_crypto_generate_key(void) {
    const char* master_password = "testpassword";
    char* key = crypto_generate_key(master_password);
    LOG_ASSERT(key != NULL, "Failed to generate key");

    printf("Generated key: %s\n", key);
    free(key);

    puts("Key generation test passed!");
}

void test_crypto_verify_key(void) {
    const char* master_password = "testpassword";
    char* key = crypto_generate_key(master_password);

    LOG_ASSERT(key != NULL, "Failed to generate key");

    bool valid = crypto_verify_key(key, master_password);
    LOG_ASSERT(valid, "key '%s' is invalid", key);

    // Test with an incorrect password
    bool invalid = crypto_verify_key(key, "wrongpassword");
    LOG_ASSERT(!invalid, "key '%s' is valid with an incorrect password", key);

    free(key);

    puts("Key verification test passed!");
}

void test_crypto_encrypt_decrypt(void) {
    const char* master_password = "testpassword";
    char* key = crypto_generate_key(master_password);

    LOG_ASSERT(key != NULL, "Failed to generate key");

    char data[] = "test data";
    size_t data_len = sizeof(data);
    size_t encrypted_len;
    size_t decrypted_len;

    // Encrypt the data
    uint8_t* encrypted_data = crypto_encrypt((uint8_t*)data, data_len, &encrypted_len, (unsigned char*)key);
    LOG_ASSERT(encrypted_data != NULL, "Failed to encrypt data");

    // Decrypt the data
    uint8_t* decrypted_data = crypto_decrypt(encrypted_data, encrypted_len, &decrypted_len, (unsigned char*)key);
    LOG_ASSERT(decrypted_data != NULL, "Failed to decrypt data");

    // Check if decrypted data matches original data
    LOG_ASSERT(decrypted_len == data_len, "Decrypted data length does not match original data length");
    LOG_ASSERT(memcmp(data, decrypted_data, data_len) == 0, "Decrypted data does not match original data");

    // Free allocated memory
    free(encrypted_data);
    free(decrypted_data);
    free(key);

    puts("Encryption and decryption test passed!");
}

// test encryption and decryption of binary data
void test_crypto_encrypt_decrypt_binary(void) {
    const char* master_password = "strong_password";
    char* key = crypto_generate_key(master_password);

    LOG_ASSERT(key != NULL, "Failed to generate key");

    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    size_t data_len = sizeof(data);
    size_t encrypted_len;

    // Encrypt the data
    uint8_t* encrypted_data = crypto_encrypt(data, data_len, &encrypted_len, (unsigned char*)key);
    LOG_ASSERT(encrypted_data != NULL, "Failed to encrypt data");

    // Decrypt the data
    size_t decrypted_len;
    uint8_t* decrypted_data = crypto_decrypt(encrypted_data, encrypted_len, &decrypted_len, (unsigned char*)key);
    LOG_ASSERT(decrypted_data != NULL, "Failed to decrypt data");

    // Check if decrypted data matches original data
    LOG_ASSERT(decrypted_len == data_len, "Decrypted data length does not match original data length");
    LOG_ASSERT(memcmp(data, decrypted_data, data_len) == 0, "Decrypted data does not match original data");

    // Free allocated memory
    free(key);
    free(encrypted_data);
    free(decrypted_data);

    puts("Binary data encryption and decryption test passed!");
}

void test_base64_encode_decode(void) {
    uint8_t data[] = "test data";
    size_t data_len = sizeof(data);

    // Encode the data
    char* encoded_data = crypto_base64_encode(data, data_len);
    LOG_ASSERT(encoded_data != NULL, "Failed to encode data");
    printf("Encoded data: %s\n", encoded_data);

    // Decode the data
    size_t decoded_len;
    uint8_t* decoded_data = crypto_base64_decode(encoded_data, &decoded_len);
    LOG_ASSERT(decoded_data != NULL, "Failed to decode data");
    assert(decoded_len == data_len);

    // null-terminate the decoded data
    decoded_data[decoded_len] = '\0';

    printf("Decoded data: %s\n", decoded_data);

    // Check if decoded data matches original data
    LOG_ASSERT(memcmp(data, decoded_data, data_len) == 0, "Decoded data does not match original data");

    // Free allocated memory
    free(encoded_data);
    free(decoded_data);

    puts("Base64 encoding and decoding test passed!");
}

void test_crypto_random_numbers(void) {
    // generate random uint64_t
    uint64_t random = crypto_random_uint64();
    LOG_ASSERT(random < UINT64_MAX, "Random number is not between 0 and UINT64_MAX");

    // generate random uint32_t
    uint32_t random2 = crypto_random_uint32();
    LOG_ASSERT(random2 < UINT32_MAX, "Random number is not between 0 and UINT32_MAX");

    // generate random uint16_t
    uint16_t random3 = crypto_random_uint16();
    LOG_ASSERT(random3 < UINT16_MAX, "Random number is not between 0 and UINT16_MAX");

    // generate random uint8_t
    uint8_t random4 = crypto_random_uint8();
    LOG_ASSERT(random4 < UINT8_MAX, "Random number is not between 0 and UINT8_MAX");

    puts("Random number generation test passed!");
}

void test_mersenne_twister(void) {
    // generate a random double between 0 and 1 100 times
    MTRand r = crypto_seedRand(548);

    for (int i = 0; i < 100; i++) {
        double random = crypto_genRand(&r);
        LOG_ASSERT(random >= 0 && random <= 1, "Random number is not between 0 and 1");
    }

    // generate random long 100 times
    for (int i = 0; i < 100; i++) {
        uint32_t random = crypto_genRandLong(&r);
        LOG_ASSERT(random <= UINT32_MAX, "Random number is not between 0 and UINT32_MAX");
    }

    // test random range
    for (int i = 0; i < 100; i++) {
        uint32_t random = crypto_randRange(10, 20);
        LOG_ASSERT(random >= 10 && random <= 20, "Random number is not between 10 and 20");
    }
}

void test_crypto_password_hash(void) {
    const char* password = "testpassword";
    char* hash = crypto_hash_password_argon2id(password);
    LOG_ASSERT(hash != NULL, "Failed to hash password");

    printf("Argon Hashed password: %s\n", hash);

    // Verify the password hash
    bool valid = crypto_verify_password_argon2id(password, hash);
    LOG_ASSERT(valid, "Password hash is invalid");

    // Test with an incorrect password
    bool invalid = crypto_verify_password_argon2id("wrongpassword", hash);
    LOG_ASSERT(!invalid, "Password hash is valid with an incorrect password");

    free(hash);

    // Brycrypt test
    char bhash[BCRYPT_HASH_SIZE];
    bool ok;
    ok = crypto_hash_password_bcrypt(password, bhash);
    LOG_ASSERT(ok, "Failed to hash password with bcrypt");

    printf("Bcrypt hashed password: %s\n", bhash);

    ok = crypto_verify_password_bcrypt(password, bhash);
    LOG_ASSERT(ok, "Bcrypt password hash is invalid");

    ok = crypto_verify_password_bcrypt("wrongpassword", bhash);
    LOG_ASSERT(!ok, "Bcrypt password hash is valid with an incorrect password");

    puts("Password hashing test passed!");
}

int main(void) {
    test_crypto_init_cleanup();
    test_crypto_generate_key();
    test_crypto_verify_key();
    test_crypto_encrypt_decrypt();
    test_crypto_encrypt_decrypt_binary();
    test_base64_encode_decode();

    test_crypto_random_numbers();
    test_mersenne_twister();
    test_crypto_password_hash();

    crypto_cleanup();

    printf("All tests passed!\n");
    return 0;
}
