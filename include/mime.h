#ifndef CEF815FD_9502_4556_B51E_B7573472FAA6
#define CEF815FD_9502_4556_B51E_B7573472FAA6

// Initialize the mime hashtable with the default mapping.
void init_mime_hashtable();

// Destroy the mime hashtable and free the memory.
void destroy_mime_hashtable();

// Returns the mime type expected for files. If your file is not included in the
// default mapping, feel-free to contribute.
// Warning: You must initialize the mime hashtable before calling this function with
// init_mime_hashtable() and destroy it after you are done with destroy_mime_hashtable().
const char* get_mimetype(char* filename);

#endif /* CEF815FD_9502_4556_B51E_B7573472FAA6 */
