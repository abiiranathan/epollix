#include "../include/urlencoded.h"

// Parse x-www-form-urlencoded form from request and return map containing fields.
// All keys and values are char*.
Map* parse_urlencoded_form(const char* url) {
    Map* params = map_create(MapConfigStr);
    if (!params) {
        return nullptr;
    }

    char* q = strstr(url, "?");
    if (!q) return nullptr;
    q++;

    char* query = strdup(q);
    if (!query) {
        perror("strdup");
        return nullptr;
    }

    char* key   = nullptr;
    char* value = nullptr;
    char *save_ptr, *save_ptr2;
    bool success = true;

    char* token = strtok_r(query, "&", &save_ptr);
    while (token != nullptr) {
        key   = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(nullptr, "=", &save_ptr2);

        if (key != nullptr && value != nullptr) {
            char* name = strdup(key);
            if (name == nullptr) {
                perror("strdup");
                success = false;
                break;
            }

            char* v = strdup(value);
            if (v == nullptr) {
                free(name);
                perror("strdup");
                success = false;
                break;
            }
            map_set(params, name, v);
        }
        token = strtok_r(nullptr, "&", &save_ptr);
    }

    free(query);

    if (!success) {
        map_destroy(params);
        return nullptr;
    }
    return params;
}

#if 0 
int main(void) {
    const char* url = "http://localhost:8080?username=nabiizy&email=example@gmail.com&password=password";
    Map* m = parse_urlencoded_form(url);
    if (!m) {
        return 1;
    }

    char *username, *email, *password;

    if ((username = map_get(m, "username"))) {
        printf("Username: %s\n", username);
    }

    if ((password = map_get(m, "password"))) {
        printf("Password: %s\n", password);
    }

    if ((email = map_get(m, "email"))) {
        printf("Email: %s\n", email);
    }

    map_destroy(m, true);
}

#endif
