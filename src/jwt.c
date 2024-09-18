#include "../include/jwt.h"
#include "../include/automem.h"
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
    autofree char* payload_str = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);

    // Base64url encode header and payload
    autofree char* encoded_header = crypto_base64_encode((unsigned char*)JWT_HEADER, header_len);
    autofree char* encoded_payload = crypto_base64_encode((unsigned char*)payload_str, strlen(payload_str));

    // Create the message to sign
    autofree char* message = (char*)malloc(strlen(encoded_header) + strlen(encoded_payload) + 2);
    sprintf(message, "%s.%s", encoded_header, encoded_payload);

    // Create the HMAC SHA-256 signature
    unsigned int len = 0;
    unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
    if (!create_hmac_sha256(secret, message, hmac, &len)) {
        return NULL;
    }
    autofree char* encoded_signature = crypto_base64_encode(hmac, len);

    // Create the JWT
    char* jwt_token = (char*)malloc(strlen(message) + strlen(encoded_signature) + 2);
    sprintf(jwt_token, "%s.%s", message, encoded_signature);

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

// Verify JWT
bool jwt_token_verify(const char* token, const char* secret, JWTPayload* p) {
    if (!secret) {
        LOG_ERROR("JWT secret is NULL.");
        return false;
    }

    // Initialize the payload
    memset(p, 0, sizeof(JWTPayload));
    memset(p->sub, 0, sizeof(p->sub));
    memset(p->data, 0, sizeof(p->data));
    p->exp = 0;

    // There must be 3 parts to the JWT
    int parts = 0;
    for (size_t i = 0; i < strlen(token); i++) {
        if (token[i] == '.')
            parts++;
    }

    if (parts != 2) {
        LOG_ERROR("Invalid JWT format.");
        return false;
    }

    // copy the token to avoid modifying the original
    autofree char* token_copy = strdup(token);

    // Split the JWT into header, payload, and signature
    char* header = strtok(token_copy, ".");
    char* payload = strtok(NULL, ".");
    char* signature = strtok(NULL, ".");

    if (!header || !payload || !signature) {
        LOG_ERROR("Invalid JWT format.");
        return false;
    }

    // Reconstruct the message
    autofree char* message = (char*)malloc(strlen(header) + strlen(payload) + 2);
    sprintf(message, "%s.%s", header, payload);

    // Create the HMAC SHA-256 signature
    unsigned int len = 0;
    unsigned char hmac[EVP_MAX_MD_SIZE] = {0};
    if (!create_hmac_sha256(secret, message, hmac, &len)) {
        return NULL;
    }

    autofree char* encoded_signature = crypto_base64_encode(hmac, len);

    // Compare the signatures
    bool result = strcmp(encoded_signature, signature) == 0;

    if (result) {
        // signature is valid. make sure the token is not expired
        size_t out_len = 0;
        autofree char* decoded_payload = (char*)crypto_base64_decode(payload, &out_len);
        if (decoded_payload) {
            result = jwt_parse_payload(decoded_payload, p);
            if (result) {
                unsigned long now = (unsigned long)time(NULL);
                result = p->exp > now;

                if (!result) {
                    LOG_ERROR("JWT token is expired.");
                }
            }
        } else {
            LOG_ERROR("Failed to decode payload.");
        }
    }
    return result;
}
