#include "../include/status.h"
#include <stddef.h>

// Array of status text strings
static const char* status_texts[] = {[StatusContinue]                      = "Continue",
                                     [StatusSwitchingProtocols]            = "Switching Protocols",
                                     [StatusProcessing]                    = "Processing",
                                     [StatusEarlyHints]                    = "Early Hints",
                                     [StatusOK]                            = "OK",
                                     [StatusCreated]                       = "Created",
                                     [StatusAccepted]                      = "Accepted",
                                     [StatusNonAuthoritativeInfo]          = "Non-Authoritative Information",
                                     [StatusNoContent]                     = "No Content",
                                     [StatusResetContent]                  = "Reset Content",
                                     [StatusPartialContent]                = "Partial Content",
                                     [StatusMultiStatus]                   = "Multi-Status",
                                     [StatusAlreadyReported]               = "Already Reported",
                                     [StatusIMUsed]                        = "IM Used",
                                     [StatusMultipleChoices]               = "Multiple Choices",
                                     [StatusMovedPermanently]              = "Moved Permanently",
                                     [StatusFound]                         = "Found",
                                     [StatusSeeOther]                      = "See Other",
                                     [StatusNotModified]                   = "Not Modified",
                                     [StatusUseProxy]                      = "Use Proxy",
                                     [StatusTemporaryRedirect]             = "Temporary Redirect",
                                     [StatusPermanentRedirect]             = "Permanent Redirect",
                                     [StatusBadRequest]                    = "Bad Request",
                                     [StatusUnauthorized]                  = "Unauthorized",
                                     [StatusPaymentRequired]               = "Payment Required",
                                     [StatusForbidden]                     = "Forbidden",
                                     [StatusNotFound]                      = "Not Found",
                                     [StatusMethodNotAllowed]              = "Method Not Allowed",
                                     [StatusNotAcceptable]                 = "Not Acceptable",
                                     [StatusProxyAuthRequired]             = "Proxy Authentication Required",
                                     [StatusRequestTimeout]                = "Request Timeout",
                                     [StatusConflict]                      = "Conflict",
                                     [StatusGone]                          = "Gone",
                                     [StatusLengthRequired]                = "Length Required",
                                     [StatusPreconditionFailed]            = "Precondition Failed",
                                     [StatusRequestEntityTooLarge]         = "Request Entity Too Large",
                                     [StatusRequestURITooLong]             = "Request URI Too Long",
                                     [StatusUnsupportedMediaType]          = "Unsupported Media Type",
                                     [StatusRequestedRangeNotSatisfiable]  = "Requested Range Not Satisfiable",
                                     [StatusExpectationFailed]             = "Expectation Failed",
                                     [StatusTeapot]                        = "I'm a teapot",
                                     [StatusMisdirectedRequest]            = "Misdirected Request",
                                     [StatusUnprocessableEntity]           = "Unprocessable Entity",
                                     [StatusLocked]                        = "Locked",
                                     [StatusFailedDependency]              = "Failed Dependency",
                                     [StatusTooEarly]                      = "Too Early",
                                     [StatusUpgradeRequired]               = "Upgrade Required",
                                     [StatusPreconditionRequired]          = "Precondition Required",
                                     [StatusTooManyRequests]               = "Too Many Requests",
                                     [StatusRequestHeaderFieldsTooLarge]   = "Request Header Fields Too Large",
                                     [StatusUnavailableForLegalReasons]    = "Unavailable For Legal Reasons",
                                     [StatusInternalServerError]           = "Internal Server Error",
                                     [StatusNotImplemented]                = "Not Implemented",
                                     [StatusBadGateway]                    = "Bad Gateway",
                                     [StatusServiceUnavailable]            = "Service Unavailable",
                                     [StatusGatewayTimeout]                = "Gateway Timeout",
                                     [StatusHTTPVersionNotSupported]       = "HTTP Version Not Supported",
                                     [StatusVariantAlsoNegotiates]         = "Variant Also Negotiates",
                                     [StatusInsufficientStorage]           = "Insufficient Storage",
                                     [StatusLoopDetected]                  = "Loop Detected",
                                     [StatusNotExtended]                   = "Not Extended",
                                     [StatusNetworkAuthenticationRequired] = "Network Authentication Required"};

// http_status_text returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go
const char* http_status_text(http_status code) {
    if (code >= StatusContinue && code <= StatusNetworkAuthenticationRequired) {
        return status_texts[code];
    }
    return "";  // Return empty string for unknown codes
}
