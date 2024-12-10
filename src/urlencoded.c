#include "../include/urlencoded.h"

// Parse x-www-form-urlencoded form from request and return map containing fields.
// All keys and values are char*.
map* parse_urlencoded_form(const char* url) {
    map* params = map_create(0, key_compare_char_ptr);
    if (!params) {
        return NULL;
    }

    char* q = strstr(url, "?");
    if (!q)
        return NULL;
    q++;

    char* query = strdup(q);
    if (!query) {
        perror("strdup");
        return NULL;
    }

    char* key = NULL;
    char* value = NULL;
    char *save_ptr, *save_ptr2;
    bool success = true;

    char* token = strtok_r(query, "&", &save_ptr);
    while (token != NULL) {
        key = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(NULL, "=", &save_ptr2);

        if (key != NULL && value != NULL) {
            char* name = strdup(key);
            if (name == NULL) {
                perror("strdup");
                success = false;
                break;
            }

            char* value = strdup(value);
            if (value == NULL) {
                free(name);
                perror("strdup");
                success = false;
                break;
            }
            map_set(params, name, value);
        }
        token = strtok_r(NULL, "&", &save_ptr);
    }

    free(query);

    if (!success) {
        map_destroy(params, true);
        return NULL;
    }
    return params;
}

#if 0 
int main(void) {
    const char* url = "http://localhost:8080?username=nabiizy&email=example@gmail.com&password=password";
    map* m = parse_urlencoded_form(url);
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
