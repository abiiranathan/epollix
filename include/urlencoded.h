#ifndef DC0A039D_E13D_431A_8975_EA341707C04A
#define DC0A039D_E13D_431A_8975_EA341707C04A

#include <solidc/map.h>

// Parse x-www-form-urlencoded form from request and return map containing fields.
// All keys and values are char*.
map* parse_urlencoded_form(const char* path);

#endif /* DC0A039D_E13D_431A_8975_EA341707C04A */
