#include "../include/jwt.h"
#include "../include/crypto.h"
#include "../include/logging.h"

#include <cjson/cJSON.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JWT_HEADER "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

// Create HMAC SHA-256 signature for the null-terminated data.
// @param key: secret key
// @param hmac_buf: buffer to write the hmac that must be EVP_MAX_MD_SIZE in size.
// The length is written to len.
bool create_hmac_sha256(const char* key, const char* data, unsigned char hmac_buf[EVP_MAX_MD_SIZE], unsigned int* len) {
    ERR_clear_error();

    // TODO: valgrind reports a memory leak here. The HMAC function is allocating memory internally.
    // TODO: However running independently, there is not trace of memory leak.
    // ???? I wonder why??
    HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)data, strlen(data), hmac_buf, len);
    if (ERR_get_error()) {
        LOG_ERROR("Failed to create HMAC SHA-256 signature.");
        return false;
    }
    return true;
}

// Generate JWT
static char* jwt_generate(const JWTPayload* payload, const char* secret) {
    static size_t header_len = strlen(JWT_HEADER);

    // convert payload to JSON
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "sub", payload->sub);
    cJSON_AddNumberToObject(json, "exp", payload->exp);
    cJSON_AddStringToObject(json, "data", payload->data);
    char* payload_str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    // Base64url encode header and payload
    char* encoded_header = crypto_base64_encode((unsigned char*)JWT_HEADER, header_len);
    char* encoded_payload = crypto_base64_encode((unsigned char*)payload_str, strlen(payload_str));

    // Create the message to sign
    char* message = (char*)malloc(strlen(encoded_header) + strlen(encoded_payload) + 2);
    sprintf(message, "%s.%s", encoded_header, encoded_payload);

    // Create the HMAC SHA-256 signature
    unsigned int len = 0;
    unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
    if (!create_hmac_sha256(secret, message, hmac, &len)) {
        free(payload_str);
        free(encoded_header);
        free(encoded_payload);
        free(message);
        return NULL;
    }
    char* encoded_signature = crypto_base64_encode(hmac, len);

    // Create the JWT
    char* jwt_token = (char*)malloc(strlen(message) + strlen(encoded_signature) + 2);
    sprintf(jwt_token, "%s.%s", message, encoded_signature);

    // Free all allocated memory except jwt_token
    free(payload_str);
    free(encoded_header);
    free(encoded_payload);
    free(message);
    free(encoded_signature);
    return jwt_token;
}

// Parse JWT payload
bool jwt_parse_payload(const char* payload, JWTPayload* p) {
    cJSON* json = cJSON_Parse(payload);
    if (json == NULL) {
        return false;
    }

    cJSON* sub = cJSON_GetObjectItemCaseSensitive(json, "sub");
    cJSON* exp = cJSON_GetObjectItemCaseSensitive(json, "exp");
    cJSON* data = cJSON_GetObjectItemCaseSensitive(json, "data");

    if (!cJSON_IsString(sub) || !cJSON_IsNumber(exp) || !cJSON_IsString(data)) {
        cJSON_Delete(json);
        return false;
    }

    if (sub) {
        strncpy(p->sub, sub->valuestring, sizeof(p->sub) - 1);
        p->sub[sizeof(p->sub) - 1] = '\0';
    }

    if (exp) {
        // convert to unsigned long
        p->exp = (unsigned long)cJSON_GetNumberValue(exp);
    }

    if (data) {
        strncpy(p->data, data->valuestring, sizeof(p->data) - 1);
        p->data[sizeof(p->data) - 1] = '\0';
    }

    cJSON_Delete(json);
    return 1;
}

char* jwt_token_create(const JWTPayload* payload, const char* secret) {
    if (secret == NULL) {
        LOG_FATAL("JWT secret is NULL.");
        return NULL;
    }

    // validate payload buffers
    if (strlen(payload->sub) == 0 || strlen(payload->data) == 0) {
        LOG_ERROR("Invalid JWT payload.");
        return NULL;
    }

    return jwt_generate(payload, secret);
}

bool jwt_token_verify(const char* token, const char* secret, JWTPayload* p) {
    if (!token || !secret || !p) {
        LOG_ERROR("Invalid input: token, secret, or payload is NULL.");
        return false;
    }

    // Initialize the payload
    memset(p, 0, sizeof(JWTPayload));

    // Validate JWT format (must have exactly two dots)
    const char* first_dot = strchr(token, '.');
    const char* second_dot = first_dot ? strchr(first_dot + 1, '.') : NULL;
    if (!first_dot || !second_dot || strchr(second_dot + 1, '.')) {
        LOG_ERROR("Invalid JWT format.");
        return false;
    }

    // Calculate lengths
    size_t header_len = first_dot - token;
    size_t payload_len = second_dot - (first_dot + 1);
    size_t signature_len = strlen(second_dot + 1);

    // Allocate memory for message (header + payload)
    size_t message_len = header_len + payload_len + 1;  // +1 for the dot
    char* message = (char*)malloc(message_len + 1);     // +1 for null terminator
    if (!message) {
        perror("Failed to allocate memory for message");
        return false;
    }

    // Construct message
    memcpy(message, token, header_len);
    message[header_len] = '.';
    memcpy(message + header_len + 1, first_dot + 1, payload_len);
    message[message_len] = '\0';

    // Create HMAC SHA-256 signature
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    if (!create_hmac_sha256(secret, message, hmac, &hmac_len)) {
        LOG_ERROR("HMAC creation failed.");
        free(message);
        return false;
    }

    // Encode HMAC to base64
    char* encoded_signature = crypto_base64_encode(hmac, hmac_len);
    if (!encoded_signature) {
        LOG_ERROR("Base64 encoding failed.");
        free(message);
        return false;
    }

    // Compare signatures
    bool signatures_match =
        (strlen(encoded_signature) == signature_len) && (memcmp(encoded_signature, second_dot + 1, signature_len) == 0);

    free(encoded_signature);

    if (!signatures_match) {
        LOG_ERROR("Signature mismatch.");
        free(message);
        return false;
    }

    // Decode payload
    size_t decoded_payload_len;
    unsigned char* decoded_payload = crypto_base64_decode(first_dot + 1, &decoded_payload_len);
    if (!decoded_payload) {
        LOG_ERROR("Failed to decode payload.");
        free(message);
        return false;
    }

    // Parse payload
    bool payload_parsed = jwt_parse_payload((char*)decoded_payload, p);
    free(decoded_payload);
    free(message);

    if (!payload_parsed) {
        LOG_ERROR("Failed to parse payload.");
        return false;
    }

    // Check expiration
    if (p->exp <= (unsigned long)time(NULL)) {
        LOG_ERROR("JWT token is expired.");
        return false;
    }

    return true;
}
