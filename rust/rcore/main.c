// Example usage of this library to parse a multipart form data
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "rcore.h"

// Get the index of the file by field name
int get_file_index(const FormData* data, const char* field_name) {
    for (uintptr_t i = 0; i < data->file_count; i++) {
        if (strcmp(data->files[i].field_name, field_name) == 0) {
            return (int)i;
        }
    }
    return -1;
}

// get the value of the field by name
const char* get_field_value(const FormData* data, const char* field_name) {
    for (uintptr_t i = 0; i < data->field_count; i++) {
        if (strcmp(data->fields[i].name, field_name) == 0) {
            return data->fields[i].value;
        }
    }
    return NULL;
}

// Get file indices by field name if multiple files are uploaded with the same field name
void get_file_indices(const FormData* data, const char* field_name, int* indices_arr, size_t array_size,
                      size_t* count) {
    *count = 0;
    for (uintptr_t i = 0; i < data->file_count; i++) {
        if (strcmp(data->files[i].field_name, field_name) == 0) {
            if (*count >= array_size) {
                break;
            }
            indices_arr[(*count)++] = (int)i;
        }
    }
}

int main() {
    char* body =
        "----WebKitFormBoundaryak4VBVRUB0vxEAhj\r\n"
        "Content-Disposition: form-data; name=\"username\"\r\n\r\n"
        "username\r\n"
        "----WebKitFormBoundaryak4VBVRUB0vxEAhj\r\n"
        "Content-Disposition: form-data; name=\"password\"\r\n\r\n"
        "password\r\n"
        "----WebKitFormBoundaryak4VBVRUB0vxEAhj\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"products.csv\"\r\n"
        "Content-Type: text/csv\r\n\r\n"
        "NAME,BRAND,COST PRICE, SELLING PRICE, QUANTITY, EXPIRY DATE\r\n"
        "Inj Ceftriaxone, Ceftriaxone, 5000, 10000, 100, 2025-12-31\r\n"
        "Tabs Paracetamol, Paracetamol, 50, 100, 200, 2025-12-31\r\n"
        "Syrup Cough Linctus, Cough Syrup, 1000, 3500, 100, 2025-12-31\r\n"
        "Inj Diclofenac, Dynapar, 2000, 5000, 100, 2025-12-31\r\n"
        "Caps Amoxicillin, Duramox, 300, 500, 100, 2025-12-31\r\n"
        "Inj Gentamicin, Gentamicin, 500, 1500, 100, 2025-12-31\r\n"
        "----WebKitFormBoundaryak4VBVRUB0vxEAhj\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"products-2.csv\"\r\n"
        "Content-Type: text/csv\r\n\r\n"
        "NAME,BRAND,COST PRICE, SELLING PRICE, QUANTITY, EXPIRY DATE\r\n"
        "Inj Ceftriaxone, Ceftriaxone, 5000, 10000, 100, 2025-12-31\r\n"
        "Tabs Paracetamol, Paracetamol, 50, 100, 200, 2025-12-31\r\n"
        "Syrup Cough Linctus, Cough Syrup, 1000, 3500, 100, 2025-12-31\r\n"
        "Inj Diclofenac, Dynapar, 2000, 5000, 100, 2025-12-31\r\n"
        "Caps Amoxicillin, Duramox, 300, 500, 100, 2025-12-31\r\n"
        "Inj Gentamicin, Gentamicin, 500, 1500, 100, 2025-12-31\r\n"
        "----WebKitFormBoundaryak4VBVRUB0vxEAhj--\r\n";

    // Parse the multipart form data
    FormData* data = parse_multipart_form_data(body);

    assert(data != NULL);
    assert(data->field_count == 2);
    assert(data->file_count == 2);
    assert(data->fields != NULL);
    assert(data->files != NULL);

    // Print the form data
    for (uintptr_t i = 0; i < data->field_count; i++) {
        printf("Field: %s = %s\n", data->fields[i].name, data->fields[i].value);
    }

    for (uintptr_t i = 0; i < data->file_count; i++) {
        printf("File(%s): %s (%s) = %lu bytes\n", data->files[i].field_name, data->files[i].filename,
               data->files[i].content_type, data->files[i].content_length);
    }

    // Get the file index by field name
    int file_index = get_file_index(data, "file");
    assert(file_index != -1);
    printf("File index: %d\n", file_index);

    // Get the value of the field by name
    const char* username = get_field_value(data, "username");
    assert(username != NULL);
    printf("Username: %s\n", username);

    const char* password = get_field_value(data, "password");
    assert(password != NULL);
    printf("Password: %s\n", password);

    // Get file indices by field name
    int file_indices[2];
    size_t count = 0;

    get_file_indices(data, "file", file_indices, 2, &count);

    assert(count == 2);
    printf("File indices: %d, %d\n", file_indices[0], file_indices[1]);

    // Free the form data
    free_multipart_form_data(data);
    return 0;
}
