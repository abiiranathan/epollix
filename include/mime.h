#ifndef CEF815FD_9502_4556_B51E_B7573472FAA6
#define CEF815FD_9502_4556_B51E_B7573472FAA6

#ifdef __cplusplus
extern "C" {
#endif

// Returns the mime type of the file based on its extension.
// If the extension is not recognized or filename is nullptr, it returns "application/octet-stream".
const char* get_mimetype(char* filename);

#ifdef __cplusplus
}
#endif

#endif /* CEF815FD_9502_4556_B51E_B7573472FAA6 */
