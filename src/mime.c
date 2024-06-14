#include "../include/mime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define an array of ExtensionContentTypeMapping
// https://mimetype.io/all-types
static const ContentTypeMapping mapping[] = {
    // Text
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

    {"c", "text/x-c"},
    {"cc", "text/x-c"},
    {"cpp", "text/x-c"},
    {"cxx", "text/x-c"},
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
    {NULL, NULL},
};

const char* getWebContentType(char* filename) {
    // Get the file extension
    char *ptr, *start = filename, *last = NULL;
    while ((ptr = strstr(start, "."))) {
        last = ptr;
        start++;
    }

    // No extension.
    if (last == NULL) {
        return "application/octet-stream";
    }

    const char* extension = last + 1;  // skip "."

    // Determine the size of the mapping array
    size_t mappingSize = sizeof(mapping) / sizeof(mapping[0]);

    // Loop through the mappings and find a matching extension
    for (size_t i = 0; i < mappingSize; i++) {
        if (strcmp(extension, mapping[i].extension) == 0) {
            return mapping[i].contentType;
        }
    }

    // Default content type if no match is found
    return "application/octet-stream";
}
