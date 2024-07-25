#include "../include/gzip.h"
#include <stdlib.h>
#include <string.h>

#define CHUNK 4096

bool gzip_compress_file(FILE* infile, FILE* outfile) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        fprintf(stderr, "Error initializing zlib\n");
        return false;
    }

    uint8_t in[CHUNK] = {0};
    uint8_t out[CHUNK] = {0};
    int ret;

    do {
        strm.avail_in = fread(in, 1, CHUNK, infile);
        if (ferror(infile)) {
            deflateEnd(&strm);
            fprintf(stderr, "Error reading from input file\n");
            return false;
        }
        strm.next_in = in;

        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;

            // Use Z_FINISH when we're at the end of the input stream
            ret = deflate(&strm, (strm.avail_in == 0) ? Z_FINISH : Z_NO_FLUSH);

            if (ret == Z_STREAM_ERROR) {
                deflateEnd(&strm);
                fprintf(stderr, "Error during compression\n");
                return false;
            }

            fwrite(out, 1, CHUNK - strm.avail_out, outfile);
            if (ferror(outfile)) {
                deflateEnd(&strm);
                fprintf(stderr, "Error writing to output file\n");
                return false;
            }

        } while (strm.avail_out == 0);  // Continue until output buffer is full

    } while (ret != Z_STREAM_END);  // Loop until compression is complete

    ret = deflateEnd(&strm);
    return ret == Z_OK;
}

// Decompress data from infile to outfile using gzip
bool gzip_decompress_file(FILE* infile, FILE* outfile) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    if (inflateInit2(&strm, 15 + 16) != Z_OK) {
        fprintf(stderr, "Error initializing zlib\n");
        return false;
    }

    uint8_t in[CHUNK] = {0};
    uint8_t out[CHUNK] = {0};
    int ret;
    do {
        strm.avail_in = fread(in, 1, CHUNK, infile);
        if (ferror(infile)) {
            inflateEnd(&strm);
            fprintf(stderr, "Error reading from input file\n");
            return false;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR; /* fall through */
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    (void)inflateEnd(&strm);
                    return false;
            }

            fwrite(out, 1, CHUNK - strm.avail_out, outfile);
            if (ferror(outfile)) {
                inflateEnd(&strm);
                fprintf(stderr, "Error writing to output file\n");
                return false;
            }
        } while (strm.avail_out == 0);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return ret == Z_STREAM_END;
}

bool gzip_compress_bytes(const uint8_t* data, size_t data_len, uint8_t** compressed_data, size_t* compressed_data_len) {
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK)
        return false;

    *compressed_data = NULL;
    *compressed_data_len = 0;

    strm.avail_in = data_len;
    strm.next_in = (unsigned char*)data;

    do {
        strm.avail_out = CHUNK;
        strm.next_out = out;
        ret = deflate(&strm, Z_FINISH); /* no bad return value */
        if (ret == Z_STREAM_ERROR) {
            deflateEnd(&strm);
            return false;
        }

        have = CHUNK - strm.avail_out;
        uint8_t* new_data = (uint8_t*)realloc(*compressed_data, *compressed_data_len + have);
        if (new_data == NULL) {
            deflateEnd(&strm);
            return false;
        }

        *compressed_data = new_data;
        memcpy(*compressed_data + *compressed_data_len, out, have);
        *compressed_data_len += have;
    } while (strm.avail_out == 0);

    /* clean up and return */
    (void)deflateEnd(&strm);

    return true;
}

bool gzip_decompress_bytes(const uint8_t* compressed_data, size_t compressed_data_len, uint8_t** uncompressed_data,
                           size_t* uncompressed_data_len) {
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, 15 + 16);
    if (ret != Z_OK) {
        fprintf(stderr, "Failed to initialize inflate: %d\n", ret);
        return false;
    }

    *uncompressed_data = NULL;
    *uncompressed_data_len = 0;

    strm.avail_in = compressed_data_len;
    strm.next_in = (unsigned char*)compressed_data;

    do {
        strm.avail_out = CHUNK;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR) {
            inflateEnd(&strm);
            fprintf(stderr, "Failed to uncompress data: %d\n", ret);
            return false;
        }

        switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR; /* fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR: {
                (void)inflateEnd(&strm);
                return false;
            }
        }

        have = CHUNK - strm.avail_out;
        uint8_t* new_data = (uint8_t*)realloc(*uncompressed_data, *uncompressed_data_len + have);
        if (new_data == NULL) {
            (void)inflateEnd(&strm);
            fprintf(stderr, "Failed to allocate memory for uncompressed data\n");
            return false;
        }

        *uncompressed_data = new_data;
        memcpy(*uncompressed_data + *uncompressed_data_len, out, have);
        *uncompressed_data_len += have;
    } while (strm.avail_out == 0);

    /* clean up and return */
    (void)inflateEnd(&strm);

    return true;
}
