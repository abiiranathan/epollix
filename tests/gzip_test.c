// test gzip file/bytes compression and decompression
#include "../include/gzip.h"
#include "../include/automem.h"
#include "../include/logging.h"

#include <solidc/filepath.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_gzip_file_compression_and_decompression() {
    autofree char* filename = make_tempfile();
    autofree char* compressed_filename = make_tempfile();

    FILE* file = fopen(filename, "wb");
    LOG_ASSERT(file, "Failed to open file for writing");

    const char* data = "Hello, World!";
    fwrite(data, 1, strlen(data), file);
    fclose(file);

    file = fopen(filename, "rb");
    LOG_ASSERT(file, "Failed to open file for reading");

    FILE* compressed_file = fopen(compressed_filename, "wb");
    LOG_ASSERT(compressed_file, "Failed to open file for writing");

    bool success = gzip_compress_file(file, compressed_file);
    fclose(file);
    fclose(compressed_file);
    LOG_ASSERT(success, "Failed to compress file");

    file = fopen(compressed_filename, "rb");
    LOG_ASSERT(file, "Failed to open compressed file for reading");

    autofree char* decompressed_filename = make_tempfile();
    compressed_file = fopen(decompressed_filename, "wb");
    LOG_ASSERT(compressed_file, "Failed to open file for writing");

    success = gzip_decompress_file(file, compressed_file);
    fclose(file);
    fclose(compressed_file);
    LOG_ASSERT(success, "Failed to decompress file");

    file = fopen(decompressed_filename, "rb");
    LOG_ASSERT(file, "Failed to open decompressed file for reading");

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    autofree char* buffer = malloc(file_size);
    fread(buffer, 1, file_size, file);
    fclose(file);

    LOG_ASSERT(strcmp(data, buffer) == 0, "Decompressed data does not match original data");

    remove(filename);
    remove(compressed_filename);
    remove(decompressed_filename);

    puts("Gzip file compression and decompression tests passed");
}

void test_gzip_bytes_compression_and_decompression() {
    const char* data = "Hello, World!";
    size_t data_len = strlen(data);

    uint8_t* compressed_data;
    size_t compressed_data_len;
    bool success = gzip_compress_bytes((const uint8_t*)data, data_len, &compressed_data, &compressed_data_len);
    LOG_ASSERT(success, "Failed to compress data");

    uint8_t* uncompressed_data;
    size_t uncompressed_data_len;
    success = gzip_decompress_bytes(compressed_data, compressed_data_len, &uncompressed_data, &uncompressed_data_len);
    LOG_ASSERT(success, "Failed to decompress data");

    LOG_ASSERT(data_len == uncompressed_data_len, "Decompressed data length does not match original data length");
    LOG_ASSERT(memcmp(data, uncompressed_data, data_len) == 0, "Decompressed data does not match original data");

    free(compressed_data);
    free(uncompressed_data);

    puts("Gzip bytes compression and decompression tests passed");
}

int main() {
    test_gzip_file_compression_and_decompression();
    test_gzip_bytes_compression_and_decompression();
    return 0;
}