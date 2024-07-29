#include "../include/mime.h"
#include "../include/logging.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    const char* extension;
    const char* contentType;
} ct_mapping;

// Define an array of file extension:content_type mapping.
// https://mimetype.io/all-types
static const ct_mapping mapping[] = {
    // Text mime types
    {"html", "text/html"},
    {"htm", "text/html"},
    {"xhtml", "application/xhtml+xml"},
    {"php", "application/x-httpd-php"},
    {"asp", "application/x-asp"},
    {"jsp", "application/x-jsp"},
    {"xml", "application/xml"},

    {"css", "text/css"},
    {"js", "application/javascript"},
    {"txt", "text/plain"},
    {"xml", "application/xml"},
    {"json", "application/json"},
    {"csv", "text/csv"},
    {"md", "text/markdown"},
    {"webmanifest", "application/manifest+json"},

    // Images
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"png", "image/png"},
    {"gif", "image/gif"},
    {"ico", "image/x-icon"},
    {"svg", "image/svg+xml"},
    {"bmp", "image/bmp"},
    {"tiff", "image/tiff"},
    {"webp", "image/webp"},

    // Documents
    {"pdf", "application/pdf"},
    {"doc", "application/msword"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"xls", "application/vnd.ms-excel"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"odt", "application/vnd.oasis.opendocument.text"},
    {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {"odp", "application/vnd.oasis.opendocument.presentation"},
    {"latex", "application/x-latex"},

    // Programming language source files
    {"c", "text/x-c"},
    {"cc", "text/x-c++"},
    {"cpp", "text/x-c++"},
    {"c++", "text/x-c++"},
    {"rs", "text/x-rust"},
    {"h", "text/x-c"},
    {"hh", "text/x-c++"},
    {"hpp", "text/x-c++"},
    {"h++", "text/x-c++"},
    {"cs", "text/x-csharp"},
    {"java", "text/x-java-source"},
    {"py", "text/x-python"},
    {"sh", "application/x-shellscript"},
    {"bat", "application/x-bat"},
    {"pl", "application/x-perl"},
    {"rb", "application/x-ruby"},
    {"php", "application/x-php"},
    {"go", "text/x-go"},
    {"swift", "text/x-swift"},
    {"lua", "text/x-lua"},
    {"r", "text/x-r"},
    {"sql", "application/sql"},
    {"asm", "text/x-asm"},
    {"s", "text/x-asm"},
    {"clj", "text/x-clojure"},
    {"lisp", "text/x-lisp"},
    {"scm", "text/x-scheme"},
    {"ss", "text/x-scheme"},
    {"rkt", "text/x-scheme"},
    {"jl", "text/x-julia"},
    {"kt", "text/x-kotlin"},
    {"dart", "text/x-dart"},
    {"scala", "text/x-scala"},
    {"groovy", "text/x-groovy"},
    {"ts", "text/typescript"},
    {"tsx", "text/typescript"},
    {"jsx", "text/jsx"},
    {"elm", "text/x-elm"},
    {"erl", "text/x-erlang"},
    {"hrl", "text/x-erlang"},
    {"ex", "text/x-elixir"},
    {"exs", "text/x-elixir"},
    {"cl", "text/x-common-lisp"},
    {"lsp", "text/x-common-lisp"},
    {"f", "text/x-fortran"},
    {"f77", "text/x-fortran"},
    {"f90", "text/x-fortran"},
    {"for", "text/x-fortran"},
    {"nim", "text/x-nim"},
    {"v", "text/x-verilog"},
    {"sv", "text/x-systemverilog"},
    {"vhd", "text/x-vhdl"},
    {"dic", "text/x-c"},
    {"h", "text/x-c"},
    {"hh", "text/x-c"},
    {"f", "text/x-fortran"},
    {"f77", "text/x-fortran"},
    {"f90", "text/x-fortran"},
    {"for", "text/x-fortran"},
    {"java", "text/x-java-source"},
    {"p", "text/x-pascal"},
    {"pas", "text/x-pascal"},
    {"pp", "text/x-pascal"},
    {"inc", "text/x-pascal"},
    {"py", "text/x-python"},

    // Other
    {"etx", "text/x-setext"},
    {"uu", "text/x-uuencode"},
    {"vcs", "text/x-vcalendar"},
    {"vcf", "text/x-vcard"},

    // Video
    {"mp4", "video/mp4"},
    {"avi", "video/avi"},
    {"mkv", "video/x-matroska"},
    {"mov", "video/quicktime"},
    {"wmv", "video/x-ms-wmv"},
    {"flv", "video/x-flv"},
    {"mpeg", "video/mpeg"},
    {"webm", "video/webm"},

    // Audio
    {"mp3", "audio/mpeg"},
    {"wav", "audio/wav"},
    {"flac", "audio/flac"},
    {"aac", "audio/aac"},
    {"ogg", "audio/ogg"},
    {"wma", "audio/x-ms-wma"},
    {"m4a", "audio/m4a"},
    {"mid", "audio/midi"},

    // Archives
    {"zip", "application/zip"},
    {"rar", "application/x-rar-compressed"},
    {"tar", "application/x-tar"},
    {"7z", "application/x-7z-compressed"},
    {"gz", "application/gzip"},
    {"bz2", "application/x-bzip2"},
    {"xz", "application/x-xz"},

    // Spreadsheets
    {"ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {"csv", "text/csv"},
    {"tsv", "text/tab-separated-values"},

    // Applications
    {"exe", "application/x-msdownload"},
    {"apk", "application/vnd.android.package-archive"},
    {"dmg", "application/x-apple-diskimage"},

    // Fonts
    {"ttf", "font/ttf"},
    {"otf", "font/otf"},
    {"woff", "font/woff"},
    {"woff2", "font/woff2"},

    // 3D Models
    {"obj", "model/obj"},
    {"stl", "model/stl"},
    {"gltf", "model/gltf+json"},

    // GIS
    {"kml", "application/vnd.google-earth.kml+xml"},
    {"kmz", "application/vnd.google-earth.kmz"},

    // Other
    {"rss", "application/rss+xml"},
    {"yaml", "application/x-yaml"},
    {"ini", "text/plain"},
    {"cfg", "text/plain"},
    {"log", "text/plain"},

    // Database Formats
    {"sqlite", "application/x-sqlite3"},
    {"sql", "application/sql"},

    // Ebooks
    {"epub", "application/epub+zip"},
    {"mobi", "application/x-mobipocket-ebook"},
    {"azw", "application/vnd.amazon.ebook"},
    {"prc", "application/x-mobipocket-ebook"},

    // Java Web Start
    {"jnlp", "application/x-java-jnlp-file"},

    // Illustration and Graphics
    {"kil", "application/x-killustrator"},
    {"kra", "application/x-krita"},
    {"krz", "application/x-krita"},

    // Microsoft Windows Applications
    {"application", "application/x-ms-application"},
    {"wmd", "application/x-ms-wmd"},
    {"wmz", "application/x-ms-wmz"},
    {"xbap", "application/x-ms-xbap"},
    {"mdb", "application/x-msaccess"},
    {"obd", "application/x-msbinder"},
    {"crd", "application/x-mscardfile"},
    {"clp", "application/x-msclip"},
    {"bat", "application/x-msdownload"},
    {"com", "application/x-msdownload"},
    {"dll", "application/x-msdownload"},
    {"exe", "application/x-msdownload"},
    {"msi", "application/x-msdownload"},
    {"m13", "application/x-msmediaview"},
    {"m14", "application/x-msmediaview"},
    {"mvb", "application/x-msmediaview"},

    // Virtual Reality (VR) and Augmented Reality (AR)
    {"vrml", "model/vrml"},
    {"glb", "model/gltf-binary"},
    {"usdz", "model/vnd.usdz+zip"},

    // CAD Files
    {"dwg", "application/dwg"},
    {"dxf", "application/dxf"},

    // Geospatial Data
    {"shp", "application/x-qgis"},
    {"geojson", "application/geo+json"},

    // Mathematical Data
    {"m", "text/x-matlab"},
    {"r", "application/R"},
    {"csv", "text/csv"},

    // Chemical Data
    {"mol", "chemical/x-mdl-molfile"},

    // Medical Imaging
    {"dicom", "application/dicom"},

    // Configuration Files
    {"yml", "application/x-yaml"},
    {"yaml", "application/x-yaml"},
    {"jsonld", "application/ld+json"},

    // Scientific Data
    {"netcdf", "application/x-netcdf"},
    {"fits", "application/fits"},
};

#define HASH_TABLE_SIZE (sizeof(mapping) / sizeof(mapping[0]))
#define DEFAULT_CONTENT_TYPE "application/octet-stream"

typedef struct HashEntry {
    const char* extension;
    const char* contentType;
    struct HashEntry* next;
} HashEntry;

// A simple hash table to store the mapping.
// Uses separate chaining for collision resolution.
static HashEntry* hashTable[HASH_TABLE_SIZE];

uint32_t hash(const char* str) {
    uint32_t hash = 0;
    while (*str) {
        hash = hash * 31 + *str++;
    }
    return hash;
}

void init_mime_hashtable(void) {
    for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
        uint32_t index = hash(mapping[i].extension) % HASH_TABLE_SIZE;
        HashEntry* entry = malloc(sizeof(HashEntry));
        if (entry == NULL) {
            LOG_FATAL("Failed to allocate memory for HashEntry\n");
        }

        entry->extension = mapping[i].extension;
        entry->contentType = mapping[i].contentType;
        entry->next = hashTable[index];
        hashTable[index] = entry;
    }
}

const char* get_mimetype(char* filename) {
    size_t len = strlen(filename);
    // Get the file extension
    char *ptr, *start = filename, *last = NULL;
    while ((ptr = strstr(start, "."))) {
        last = ptr;
        start++;
    }

    // No extension.
    if (last == NULL) {
        return DEFAULT_CONTENT_TYPE;
    }

    char* extension = last + 1;  // skip "."
    char* end = filename + len;

    size_t ext_len = end - extension;
    if (ext_len == 0) {
        return DEFAULT_CONTENT_TYPE;
    }

    if (ext_len > 255) {
        LOG_ERROR("File extension is too long: %s", extension);
        return DEFAULT_CONTENT_TYPE;
    }

    char file_extension[256] = {0};
    strncpy(file_extension, extension, sizeof(file_extension) - 1);
    file_extension[ext_len] = '\0';

    // convert extension to lowercase
    for (size_t i = 0; i < ext_len; i++) {
        file_extension[i] = tolower(file_extension[i]);
    }

    uint32_t index = hash(file_extension) % HASH_TABLE_SIZE;
    HashEntry* entry = hashTable[index];

    while (entry) {
        if (strcasecmp(file_extension, entry->extension) == 0) {
            return entry->contentType;
        }
        entry = entry->next;
    }
    return DEFAULT_CONTENT_TYPE;
}

void destroy_mime_hashtable(void) {
    for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
        HashEntry* entry = hashTable[i];
        while (entry) {
            HashEntry* temp = entry;
            entry = entry->next;
            free(temp);
        }
    }
}
