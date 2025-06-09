#include "../include/mime.h"
#include <ctype.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// Includes provided by hmap dependency.
// Dependent on cmake finding it.
#include "hmap.h"

#define DEFAULT_CONTENT_TYPE "application/octet-stream"

// The hashmap entry for each mime type.
typedef struct {
    HNode node;
    const char* ext;
    const char* mimetype;
} MimeEntry;

// Define an array of file extension:content_type mapping.
// https://mimetype.io/all-types
static MimeEntry entries[] = {
    // Text mime types
    {.ext = "html", .mimetype = "text/html"},
    {.ext = "htm", .mimetype = "text/html"},
    {.ext = "xhtml", .mimetype = "application/xhtml+xml"},
    {.ext = "php", .mimetype = "application/x-httpd-php"},
    {.ext = "asp", .mimetype = "application/x-asp"},
    {.ext = "jsp", .mimetype = "application/x-jsp"},
    {.ext = "xml", .mimetype = "application/xml"},

    {.ext = "css", .mimetype = "text/css"},
    {.ext = "js", .mimetype = "application/javascript"},
    {.ext = "txt", .mimetype = "text/plain"},
    {.ext = "json", .mimetype = "application/json"},
    {.ext = "csv", .mimetype = "text/csv"},
    {.ext = "md", .mimetype = "text/markdown"},
    {.ext = "webmanifest", .mimetype = "application/manifest+json"},

    // Images
    {.ext = "jpg", .mimetype = "image/jpeg"},
    {.ext = "jpeg", .mimetype = "image/jpeg"},
    {.ext = "png", .mimetype = "image/png"},
    {.ext = "gif", .mimetype = "image/gif"},
    {.ext = "ico", .mimetype = "image/x-icon"},
    {.ext = "svg", .mimetype = "image/svg+xml"},
    {.ext = "bmp", .mimetype = "image/bmp"},
    {.ext = "tiff", .mimetype = "image/tiff"},
    {.ext = "webp", .mimetype = "image/webp"},

    // Documents
    {.ext = "pdf", .mimetype = "application/pdf"},
    {.ext = "doc", .mimetype = "application/msword"},
    {.ext = "docx", .mimetype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {.ext = "pptx", .mimetype = "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {.ext = "xls", .mimetype = "application/vnd.ms-excel"},
    {.ext = "xlsx", .mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {.ext = "odt", .mimetype = "application/vnd.oasis.opendocument.text"},
    {.ext = "ods", .mimetype = "application/vnd.oasis.opendocument.spreadsheet"},
    {.ext = "odp", .mimetype = "application/vnd.oasis.opendocument.presentation"},
    {.ext = "latex", .mimetype = "application/x-latex"},

    // Programming language source files
    {.ext = "c", .mimetype = "text/x-c"},
    {.ext = "cc", .mimetype = "text/x-c++"},
    {.ext = "cpp", .mimetype = "text/x-c++"},
    {.ext = "c++", .mimetype = "text/x-c++"},
    {.ext = "rs", .mimetype = "text/x-rust"},
    {.ext = "h", .mimetype = "text/x-c"},
    {.ext = "hh", .mimetype = "text/x-c++"},
    {.ext = "hpp", .mimetype = "text/x-c++"},
    {.ext = "h++", .mimetype = "text/x-c++"},
    {.ext = "cs", .mimetype = "text/x-csharp"},
    {.ext = "java", .mimetype = "text/x-java-source"},
    {.ext = "py", .mimetype = "text/x-python"},
    {.ext = "sh", .mimetype = "application/x-shellscript"},
    {.ext = "bat", .mimetype = "application/x-bat"},
    {.ext = "pl", .mimetype = "application/x-perl"},
    {.ext = "rb", .mimetype = "application/x-ruby"},
    {.ext = "php", .mimetype = "application/x-php"},
    {.ext = "go", .mimetype = "text/x-go"},
    {.ext = "swift", .mimetype = "text/x-swift"},
    {.ext = "lua", .mimetype = "text/x-lua"},
    {.ext = "r", .mimetype = "text/x-r"},
    {.ext = "sql", .mimetype = "application/sql"},
    {.ext = "asm", .mimetype = "text/x-asm"},
    {.ext = "s", .mimetype = "text/x-asm"},
    {.ext = "clj", .mimetype = "text/x-clojure"},
    {.ext = "lisp", .mimetype = "text/x-lisp"},
    {.ext = "scm", .mimetype = "text/x-scheme"},
    {.ext = "ss", .mimetype = "text/x-scheme"},
    {.ext = "rkt", .mimetype = "text/x-scheme"},
    {.ext = "jl", .mimetype = "text/x-julia"},
    {.ext = "kt", .mimetype = "text/x-kotlin"},
    {.ext = "dart", .mimetype = "text/x-dart"},
    {.ext = "scala", .mimetype = "text/x-scala"},
    {.ext = "groovy", .mimetype = "text/x-groovy"},
    {.ext = "ts", .mimetype = "text/typescript"},
    {.ext = "tsx", .mimetype = "text/typescript"},
    {.ext = "jsx", .mimetype = "text/jsx"},
    {.ext = "elm", .mimetype = "text/x-elm"},
    {.ext = "erl", .mimetype = "text/x-erlang"},
    {.ext = "hrl", .mimetype = "text/x-erlang"},
    {.ext = "ex", .mimetype = "text/x-elixir"},
    {.ext = "exs", .mimetype = "text/x-elixir"},
    {.ext = "cl", .mimetype = "text/x-common-lisp"},
    {.ext = "lsp", .mimetype = "text/x-common-lisp"},
    {.ext = "f", .mimetype = "text/x-fortran"},
    {.ext = "f77", .mimetype = "text/x-fortran"},
    {.ext = "f90", .mimetype = "text/x-fortran"},
    {.ext = "for", .mimetype = "text/x-fortran"},
    {.ext = "nim", .mimetype = "text/x-nim"},
    {.ext = "v", .mimetype = "text/x-verilog"},
    {.ext = "sv", .mimetype = "text/x-systemverilog"},
    {.ext = "vhd", .mimetype = "text/x-vhdl"},
    {.ext = "dic", .mimetype = "text/x-c"},
    {.ext = "h", .mimetype = "text/x-c"},
    {.ext = "hh", .mimetype = "text/x-c"},
    {.ext = "f", .mimetype = "text/x-fortran"},
    {.ext = "f77", .mimetype = "text/x-fortran"},
    {.ext = "f90", .mimetype = "text/x-fortran"},
    {.ext = "for", .mimetype = "text/x-fortran"},
    {.ext = "java", .mimetype = "text/x-java-source"},
    {.ext = "p", .mimetype = "text/x-pascal"},
    {.ext = "pas", .mimetype = "text/x-pascal"},
    {.ext = "pp", .mimetype = "text/x-pascal"},
    {.ext = "inc", .mimetype = "text/x-pascal"},
    {.ext = "py", .mimetype = "text/x-python"},

    // Other
    {.ext = "etx", .mimetype = "text/x-setext"},
    {.ext = "uu", .mimetype = "text/x-uuencode"},
    {.ext = "vcs", .mimetype = "text/x-vcalendar"},
    {.ext = "vcf", .mimetype = "text/x-vcard"},

    // Video
    {.ext = "mp4", .mimetype = "video/mp4"},
    {.ext = "avi", .mimetype = "video/avi"},
    {.ext = "mkv", .mimetype = "video/x-matroska"},
    {.ext = "mov", .mimetype = "video/quicktime"},
    {.ext = "wmv", .mimetype = "video/x-ms-wmv"},
    {.ext = "flv", .mimetype = "video/x-flv"},
    {.ext = "mpeg", .mimetype = "video/mpeg"},
    {.ext = "webm", .mimetype = "video/webm"},

    // Audio
    {.ext = "mp3", .mimetype = "audio/mpeg"},
    {.ext = "wav", .mimetype = "audio/wav"},
    {.ext = "flac", .mimetype = "audio/flac"},
    {.ext = "aac", .mimetype = "audio/aac"},
    {.ext = "ogg", .mimetype = "audio/ogg"},
    {.ext = "wma", .mimetype = "audio/x-ms-wma"},
    {.ext = "m4a", .mimetype = "audio/m4a"},
    {.ext = "mid", .mimetype = "audio/midi"},

    // Archives
    {.ext = "zip", .mimetype = "application/zip"},
    {.ext = "rar", .mimetype = "application/x-rar-compressed"},
    {.ext = "tar", .mimetype = "application/x-tar"},
    {.ext = "7z", .mimetype = "application/x-7z-compressed"},
    {.ext = "gz", .mimetype = "application/gzip"},
    {.ext = "bz2", .mimetype = "application/x-bzip2"},
    {.ext = "xz", .mimetype = "application/x-xz"},

    // Spreadsheets
    {.ext = "ods", .mimetype = "application/vnd.oasis.opendocument.spreadsheet"},
    {.ext = "csv", .mimetype = "text/csv"},
    {.ext = "tsv", .mimetype = "text/tab-separated-values"},

    // Applications
    {.ext = "exe", .mimetype = "application/x-msdownload"},
    {.ext = "apk", .mimetype = "application/vnd.android.package-archive"},
    {.ext = "dmg", .mimetype = "application/x-apple-diskimage"},

    // Fonts
    {.ext = "ttf", .mimetype = "font/ttf"},
    {.ext = "otf", .mimetype = "font/otf"},
    {.ext = "woff", .mimetype = "font/woff"},
    {.ext = "woff2", .mimetype = "font/woff2"},

    // 3D Models
    {.ext = "obj", .mimetype = "model/obj"},
    {.ext = "stl", .mimetype = "model/stl"},
    {.ext = "gltf", .mimetype = "model/gltf+json"},

    // GIS
    {.ext = "kml", .mimetype = "application/vnd.google-earth.kml+xml"},
    {.ext = "kmz", .mimetype = "application/vnd.google-earth.kmz"},

    // Other
    {.ext = "rss", .mimetype = "application/rss+xml"},
    {.ext = "yaml", .mimetype = "application/x-yaml"},
    {.ext = "ini", .mimetype = "text/plain"},
    {.ext = "cfg", .mimetype = "text/plain"},
    {.ext = "log", .mimetype = "text/plain"},

    // Database Formats
    {.ext = "sqlite", .mimetype = "application/x-sqlite3"},
    {.ext = "sql", .mimetype = "application/sql"},

    // Ebooks
    {.ext = "epub", .mimetype = "application/epub+zip"},
    {.ext = "mobi", .mimetype = "application/x-mobipocket-ebook"},
    {.ext = "azw", .mimetype = "application/vnd.amazon.ebook"},
    {.ext = "prc", .mimetype = "application/x-mobipocket-ebook"},

    // Microsoft Windows Applications
    {.ext = "wmd", .mimetype = "application/x-ms-wmd"},
    {.ext = "wmz", .mimetype = "application/x-ms-wmz"},
    {.ext = "xbap", .mimetype = "application/x-ms-xbap"},
    {.ext = "mdb", .mimetype = "application/x-msaccess"},
    {.ext = "obd", .mimetype = "application/x-msbinder"},
    {.ext = "crd", .mimetype = "application/x-mscardfile"},
    {.ext = "clp", .mimetype = "application/x-msclip"},
    {.ext = "bat", .mimetype = "application/x-msdownload"},
    {.ext = "com", .mimetype = "application/x-msdownload"},
    {.ext = "dll", .mimetype = "application/x-msdownload"},
    {.ext = "exe", .mimetype = "application/x-msdownload"},
    {.ext = "msi", .mimetype = "application/x-msdownload"},
    {.ext = "m13", .mimetype = "application/x-msmediaview"},
    {.ext = "m14", .mimetype = "application/x-msmediaview"},
    {.ext = "mvb", .mimetype = "application/x-msmediaview"},

    // Virtual Reality (VR) and Augmented Reality (AR)
    {.ext = "vrml", .mimetype = "model/vrml"},
    {.ext = "glb", .mimetype = "model/gltf-binary"},
    {.ext = "usdz", .mimetype = "model/vnd.usdz+zip"},

    // CAD Files
    {.ext = "dwg", .mimetype = "application/dwg"},
    {.ext = "dxf", .mimetype = "application/dxf"},

    // Geospatial Data
    {.ext = "shp", .mimetype = "application/x-qgis"},
    {.ext = "geojson", .mimetype = "application/geo+json"},

    // configuration
    {.ext = "jsonld", .mimetype = "application/ld+json"},

    // Mathematical Data
    {.ext = "m", .mimetype = "text/x-matlab"},
    {.ext = "r", .mimetype = "application/R"},
    {.ext = "csv", .mimetype = "text/csv"},

    // Chemical Data
    {.ext = "mol", .mimetype = "chemical/x-mdl-molfile"},

    // Medical Imaging
    {.ext = "dicom", .mimetype = "application/dicom"},

    // Configuration Files
    {.ext = "yml", .mimetype = "application/x-yaml"},
    {.ext = "yaml", .mimetype = "application/x-yaml"},
    {.ext = "jsonld", .mimetype = "application/ld+json"},

    // Scientific Data
    {.ext = "netcdf", .mimetype = "application/x-netcdf"},
    {.ext = "fits", .mimetype = "application/fits"},
};

#define MIME_MAPPING_SIZE (sizeof(entries) / sizeof(entries[0]))

// Global map for the mime types.
static HMap m_dict = {};

__attribute__((constructor())) void init_mime_types() {
    hm_reserve(&m_dict, NEXT_POWER_OF_TWO(MIME_MAPPING_SIZE));

    for (size_t i = 0; i < MIME_MAPPING_SIZE; i++) {
        MimeEntry* entry  = &entries[i];
        entry->node.hcode = hm_strhash(entry->ext);
        hm_insert(&m_dict, &entry->node);
    }
}

__attribute__((destructor())) void cleanup_mimetypes() {
    hm_clear(&m_dict);
}

static bool mime_eq(HNode* lhs, HNode* rhs) {
    MimeEntry* a = container_of(lhs, MimeEntry, node);
    MimeEntry* b = container_of(rhs, MimeEntry, node);
    return strcmp(a->ext, b->ext) == 0;
}

const char* get_mimetype(char* filename) {
    if (!filename) {
        return DEFAULT_CONTENT_TYPE;
    }

    // Get the file extension.
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
    char ext[32];
    strlcpy(ext, extension, sizeof(ext));  // always null-terminates

    // Convert to lowercase
    for (char* p = ext; *p; ++p) {
        *p = tolower((unsigned char)*p);
    }

    MimeEntry entry = {.ext = ext, .node.hcode = hm_strhash(ext)};
    HNode* found    = hm_lookup(&m_dict, &entry.node, mime_eq);
    if (found) {
        return container_of(found, MimeEntry, node)->mimetype;
    }
    return DEFAULT_CONTENT_TYPE;
}
