#include "../include/crypto.h"
#include "../deps/libbcrypt/bcrypt.h"

#include <math.h>
#include <string.h>

void crypto_init(void) {
    // Initialize the sodium library
    if (sodium_init() == -1) {
        LOG_FATAL("Failed to initialize the sodium library");
    }

    // Initialize the OpenSSL library
    OpenSSL_add_all_algorithms();

    // Initialize the crypto library
    int ret = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    if (ret != 1) {
        LOG_FATAL("Failed to initialize the crypto library");
    }

    // Initialize the random number generator
    ret = RAND_poll();
    if (ret != 1) {
        LOG_FATAL("Failed to initialize the random number generator");
    }
}

void crypto_cleanup(void) {
    // clean up all data
    CRYPTO_cleanup_all_ex_data();

    // Cleanup the OpenSSL library
    EVP_cleanup();

    // Cleanup the crypto library
    OPENSSL_cleanup();
}

char* crypto_generate_key(const char* master_password) {
    // Generate a random salt
    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    // Derive the key using the master password and the salt
    uint8_t derived_key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(derived_key, sizeof(derived_key), master_password, strlen(master_password), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        LOG_ERROR("Failed to derive the key");
        return NULL;
    }

    // Buffer to hold the salt and the derived key
    uint8_t key_with_salt[crypto_pwhash_SALTBYTES + crypto_secretbox_KEYBYTES];

    // Copy the salt to the beginning of the buffer
    memcpy(key_with_salt, salt, sizeof(salt));

    // Copy the derived key after the salt
    memcpy(key_with_salt + sizeof(salt), derived_key, sizeof(derived_key));

    // Encode the salt and derived key
    size_t key_with_salt_len = sizeof(key_with_salt);
    size_t max_hex_len = key_with_salt_len * 2 + 1;
    char* encoded_key = (char*)malloc(max_hex_len);
    if (encoded_key == NULL) {
        LOG_FATAL("Failed to allocate memory for the encoded key");
    }

    sodium_bin2hex(encoded_key, max_hex_len, key_with_salt, key_with_salt_len);
    return encoded_key;
}

bool crypto_verify_key(const char* encoded_key, const char* master_password) {
    // Calculate the length of the binary data
    size_t key_with_salt_len = strlen(encoded_key) / 2;
    uint8_t* key_with_salt = (uint8_t*)malloc(key_with_salt_len);
    if (key_with_salt == NULL) {
        LOG_FATAL("Failed to allocate memory for the key with salt");
    }

    // Decode the hex string back to binary
    if (sodium_hex2bin(key_with_salt, key_with_salt_len, encoded_key, strlen(encoded_key), NULL, NULL, NULL) != 0) {
        LOG_ERROR("Failed to decode the hex string");
        free(key_with_salt);
        return false;
    }

    // Extract the salt from the decoded binary data
    uint8_t salt[crypto_pwhash_SALTBYTES];
    memcpy(salt, key_with_salt, crypto_pwhash_SALTBYTES);

    // Derive the key using the master password and extracted salt
    uint8_t derived_key[crypto_secretbox_KEYBYTES];
    if (crypto_pwhash(derived_key, sizeof(derived_key), master_password, strlen(master_password), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        LOG_ERROR("Failed to derive the key");
        free(key_with_salt);
        return false;
    }

    // Compare the derived key with the stored derived key
    bool result = (memcmp(derived_key, key_with_salt + crypto_pwhash_SALTBYTES, crypto_secretbox_KEYBYTES) == 0);

    // Clean up
    free(key_with_salt);
    return result;
}

uint8_t* crypto_encrypt(const uint8_t* data, size_t data_len, size_t* out_len, const unsigned char* secret_key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("Failed to initialize EVP_CIPHER_CTX");
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret_key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("Failed to initialize encryption");
        return NULL;
    }

    int len;
    int ciphertext_len = 0;
    int block_size = EVP_CIPHER_block_size(EVP_aes_128_ecb());

    // Allocate buffer for ciphertext
    uint8_t* ciphertext = (uint8_t*)malloc(data_len + block_size);
    if (ciphertext == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("Failed to allocate memory for ciphertext");
        return NULL;
    }

    // Encrypt the data
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, data, data_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("Failed to encrypt data");
        return NULL;
    }

    ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("Failed to finalize encryption");
        return NULL;
    }

    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Reallocate buffer to fit the exact ciphertext length
    uint8_t* trimmed_ciphertext = (uint8_t*)realloc(ciphertext, ciphertext_len);
    if (trimmed_ciphertext == NULL) {
        free(ciphertext);
        LOG_ERROR("Failed to reallocate memory for ciphertext");
        return NULL;
    }

    *out_len = ciphertext_len;
    return trimmed_ciphertext;
}

uint8_t* crypto_decrypt(const uint8_t* data, size_t data_len, size_t* out_len, const unsigned char* secret_key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, secret_key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len;
    int ciphertext_len = 0;
    int block_size = EVP_CIPHER_block_size(EVP_aes_128_ecb());

    // Allocate buffer for plaintext
    uint8_t* cipher_text = (uint8_t*)malloc(data_len + block_size);
    if (cipher_text == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Decrypt the data
    if (EVP_DecryptUpdate(ctx, cipher_text, &len, data, data_len) != 1) {
        free(cipher_text);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len = len;

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, cipher_text + len, &len) != 1) {
        free(cipher_text);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Reallocate buffer to fit the exact plaintext length
    uint8_t* trimmed_data = (uint8_t*)realloc(cipher_text, ciphertext_len);
    if (trimmed_data == NULL) {
        free(cipher_text);
        return NULL;
    }

    *out_len = ciphertext_len;
    return trimmed_data;
}

// base64 encode raw bytes. It can be used to encode the key.
char* crypto_base64_encode(uint8_t* data, size_t data_len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // Disable newlines
    BIO_write(bio, data, data_len);
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);

    char* b64text = (char*)malloc(bufferPtr->length + 1);  // +1 for null terminator
    if (b64text == NULL) {
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';  // Null-terminate the string

    BIO_free_all(bio);

    return b64text;
}

// base64 decode raw bytes to a string.
uint8_t* crypto_base64_decode(const char* data, size_t* out_len) {
    // Check for valid input
    if (data == NULL || out_len == NULL) {
        return NULL;
    }

    // Use OpenSSL for Base64 decoding
    BIO *bio_mem, *bio_b64;
    uint8_t* buffer;
    int decode_len = 0;
    long len = strlen(data);

    // Create memory BIO for encoded data
    bio_mem = BIO_new_mem_buf((void*)data, len);
    if (bio_mem == NULL) {
        return NULL;
    }

    // Create Base64 filter BIO
    bio_b64 = BIO_new(BIO_f_base64());
    if (bio_b64 == NULL) {
        BIO_free_all(bio_mem);
        return NULL;
    }

    // Set decode mode, no newline characters expected
    BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);

    // Chain the BIOs
    bio_b64 = BIO_push(bio_b64, bio_mem);

    // Allocate buffer for decoded data with a safe estimate
    buffer = (uint8_t*)malloc(len);
    if (buffer == NULL) {
        BIO_free_all(bio_b64);
        return NULL;
    }

    memset(buffer, 0, len);

    // Decode the data
    decode_len = BIO_read(bio_b64, buffer, len);
    if (decode_len < 0) {
        free(buffer);
        BIO_free_all(bio_b64);
        return NULL;
    }

    // Set the output length
    *out_len = (size_t)decode_len;

    // Free the BIO chain
    BIO_free_all(bio_b64);

    return buffer;
}

/* Reusable function to generate random bytes using ChaCha20 */
bool crypto_random_bytes(uint8_t* out, size_t out_len) {
    // Generate key and IV
    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t iv[CHACHA20_IV_SIZE];

    if (1 != RAND_bytes(key, sizeof(key)) || 1 != RAND_bytes(iv, sizeof(iv))) {
        LOG_ERROR("Failed to generate random bytes");
        return false;
    }

    // Initialize ChaCha20 context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        LOG_ERROR("Failed to initialize EVP_CIPHER_CTX");
        return false;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("Failed to initialize ChaCha20 context");
        return false;
    }

    int len;
    uint8_t in[1] = {0};  // Input is zero-filled for RNG purposes
    if (1 != EVP_EncryptUpdate(ctx, out, &len, in, out_len)) {
        EVP_CIPHER_CTX_free(ctx);
        LOG_ERROR("Failed to generate random bytes");
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

uint64_t crypto_random_uint64(void) {
    uint64_t random_bytes;
    crypto_random_bytes((uint8_t*)&random_bytes, sizeof(random_bytes));
    return random_bytes;
}

uint32_t crypto_random_uint32(void) {
    uint32_t random_bytes;
    crypto_random_bytes((uint8_t*)&random_bytes, sizeof(random_bytes));
    return random_bytes;
}

uint16_t crypto_random_uint16(void) {
    uint16_t random_bytes;
    crypto_random_bytes((uint8_t*)&random_bytes, sizeof(random_bytes));
    return random_bytes;
}

uint8_t crypto_random_uint8(void) {
    uint8_t random_bytes;
    crypto_random_bytes((uint8_t*)&random_bytes, sizeof(random_bytes));
    return random_bytes;
}

// ============ FASTER NON-CRYPTOGRAPHIC RANDOM NUMBER GENERATOR ============
// Generates a random uint64_t using the Mersenne Twister algorithm.

/* An implementation of the MT19937 Algorithm for the Mersenne Twister
 * by Evan Sultanik.  Based upon the pseudocode in: M. Matsumoto and
 * T. Nishimura, "Mersenne Twister: A 623-dimensionally
 * equidistributed uniform pseudorandom number generator," ACM
 * Transactions on Modeling and Computer Simulation Vol. 8, No. 1,
 * January pp.3-30 1998.
 *
 * http://www.sultanik.com/Mersenne_twister
 */

#define UPPER_MASK 0x80000000
#define LOWER_MASK 0x7fffffff
#define TEMPERING_MASK_B 0x9d2c5680
#define TEMPERING_MASK_C 0xefc60000

inline static void m_seedRand(MTRand* rand, uint32_t seed) {
    /* set initial seeds to mt[STATE_VECTOR_LENGTH] using the generator
   * from Line 25 of Table 1 in: Donald Knuth, "The Art of Computer
   * Programming," Vol. 2 (2nd Ed.) pp.102.
   */
    rand->mt[0] = seed & 0xffffffff;
    for (rand->index = 1; rand->index < STATE_VECTOR_LENGTH; rand->index++) {
        rand->mt[rand->index] = (6069 * rand->mt[rand->index - 1]) & 0xffffffff;
    }
}

/**
* Creates a new random number generator from a given seed.
*/
MTRand crypto_seedRand(uint32_t seed) {
    MTRand rand;
    m_seedRand(&rand, seed);
    return rand;
}

/**
 * Generates a pseudo-randomly generated long.
 */
uint32_t crypto_genRandLong(MTRand* rand) {
    uint32_t y;
    static uint32_t mag[2] = {0x0, 0x9908b0df}; /* mag[x] = x * 0x9908b0df for x = 0,1 */
    if (rand->index >= STATE_VECTOR_LENGTH || rand->index < 0) {
        /* generate STATE_VECTOR_LENGTH words at a time */
        int32_t kk;
        if (rand->index >= STATE_VECTOR_LENGTH + 1 || rand->index < 0) {
            m_seedRand(rand, 4357);
        }
        for (kk = 0; kk < STATE_VECTOR_LENGTH - STATE_VECTOR_M; kk++) {
            y = (rand->mt[kk] & UPPER_MASK) | (rand->mt[kk + 1] & LOWER_MASK);
            rand->mt[kk] = rand->mt[kk + STATE_VECTOR_M] ^ (y >> 1) ^ mag[y & 0x1];
        }
        for (; kk < STATE_VECTOR_LENGTH - 1; kk++) {
            y = (rand->mt[kk] & UPPER_MASK) | (rand->mt[kk + 1] & LOWER_MASK);
            rand->mt[kk] = rand->mt[kk + (STATE_VECTOR_M - STATE_VECTOR_LENGTH)] ^ (y >> 1) ^ mag[y & 0x1];
        }
        y = (rand->mt[STATE_VECTOR_LENGTH - 1] & UPPER_MASK) | (rand->mt[0] & LOWER_MASK);
        rand->mt[STATE_VECTOR_LENGTH - 1] = rand->mt[STATE_VECTOR_M - 1] ^ (y >> 1) ^ mag[y & 0x1];
        rand->index = 0;
    }
    y = rand->mt[rand->index++];
    y ^= (y >> 11);
    y ^= (y << 7) & TEMPERING_MASK_B;
    y ^= (y << 15) & TEMPERING_MASK_C;
    y ^= (y >> 18);
    return y;
}

/**
 * Generates a pseudo-randomly generated double in the range [0..1].
 */
double crypto_genRand(MTRand* rand) {
    return ((double)crypto_genRandLong(rand) / (uint32_t)0xffffffff);
}

// Generates a random uint32_t between min and max using the Mersenne Twister algorithm.
uint32_t crypto_randRange(uint32_t min, uint32_t max) {
    MTRand rand = crypto_seedRand(crypto_random_uint32());
    return (crypto_genRandLong(&rand) % (max - min + 1)) + min;
}

// Password hashing with Argon2id. This function returns the encoded password.
// Note that this is slower than bcrypt but more secure.
char* crypto_hash_password_argon2id(const char* password) {
    // Ensure the password is not NULL
    if (password == NULL) {
        LOG_ERROR("Password is NULL");
        return NULL;
    }

    // Hash the password using Argon2id
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password, strlen(password), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        LOG_ERROR("Failed to hash the password");
        return NULL;
    }

    // Allocate memory for the encoded password
    char* encoded = (char*)malloc(crypto_pwhash_STRBYTES);
    if (encoded == NULL) {
        LOG_FATAL("Failed to allocate memory for the encoded password");
    }

    // Copy the hashed password to the allocated memory
    strncpy(encoded, hash, crypto_pwhash_STRBYTES);

    return encoded;
}

bool crypto_verify_password_argon2id(const char* password, const char* hash) {
    // Ensure the hashed password and password are not NULL
    if (hash == NULL || password == NULL) {
        LOG_ERROR("Hashed password or password is NULL");
        return false;
    }

    // Verify the password against the hashed password
    if (crypto_pwhash_str_verify(hash, password, strlen(password)) != 0) {
        // Incorrect password
        return false;
    }

    // Correct password
    return true;
}

// Hash user passwords using bcrypt. Note that bcrypt is faster than Argon2id but less secure.
// The hash is stored in the hash buffer. Returns true if successful.
bool crypto_hash_password_bcrypt(const char* password, char hash[BCRYPT_HASH_SIZE]) {
    char salt[BCRYPT_HASH_SIZE];
    if (bcrypt_gensalt(12, salt) != 0)
        return false;
    if (bcrypt_hashpw(password, salt, hash) != 0) {
        return false;
    }
    return true;
}

// Check if the password matches the hash
bool crypto_verify_password_bcrypt(const char* password, const char* hash) {
    return bcrypt_checkpw(password, hash) == 0;
}