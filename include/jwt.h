#ifndef JWT_H
#define JWT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

// JWT Token secret environment variable name
#define JWT_TOKEN_SECRET "JWT_TOKEN_SECRET"

// JWT Payload struct definition
typedef struct {
    char sub[256];      // Subject representing the user ID
    unsigned long exp;  // Expiration time as a UNIX timestamp
    char data[256];     // JSON data representing the user data
} JWTPayload;

// Create JWT directly.
// The caller is responsible for freeing the returned buffer.
char* jwt_token_create(const JWTPayload* payload, const char* secret);

// Function to verify the JWT
bool jwt_token_verify(const char* token, const char* secret, JWTPayload* p);

// Function to parse the payload
bool jwt_parse_payload(const char* payload, JWTPayload* p);

#ifdef __cplusplus
}
#endif

#endif  // JWT_H
