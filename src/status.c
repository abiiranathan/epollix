#include "../include/status.h"
#include <stddef.h>

// http_status_text returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go
const char * http_status_text(http_status code) {
    switch (code) {
        case StatusContinue:
            return "Continue";
        case StatusSwitchingProtocols:
            return "Switching Protocols";
        case StatusProcessing:
            return "Processing";
        case StatusEarlyHints:
            return "Early Hints";
        case StatusOK:
            return "OK";
        case StatusCreated:
            return "Created";
        case StatusAccepted:
            return "Accepted";
        case StatusNonAuthoritativeInfo:
            return "Non-Authoritative Information";
        case StatusNoContent:
            return "No Content";
        case StatusResetContent:
            return "Reset Content";
        case StatusPartialContent:
            return "Partial Content";
        case StatusMultiStatus:
            return "Multi-Status";
        case StatusAlreadyReported:
            return "Already Reported";
        case StatusIMUsed:
            return "IM Used";
        case StatusMultipleChoices:
            return "Multiple Choices";
        case StatusMovedPermanently:
            return "Moved Permanently";
        case StatusFound:
            return "Found";
        case StatusSeeOther:
            return "See Other";
        case StatusNotModified:
            return "Not Modified";
        case StatusUseProxy:
            return "Use Proxy";
        case StatusTemporaryRedirect:
            return "Temporary Redirect";
        case StatusPermanentRedirect:
            return "Permanent Redirect";
        case StatusBadRequest:
            return "Bad Request";
        case StatusUnauthorized:
            return "Unauthorized";
        case StatusPaymentRequired:
            return "Payment Required";
        case StatusForbidden:
            return "Forbidden";
        case StatusNotFound:
            return "Not Found";
        case StatusMethodNotAllowed:
            return "Method Not Allowed";
        case StatusNotAcceptable:
            return "Not Acceptable";
        case StatusProxyAuthRequired:
            return "Proxy Authentication Required";
        case StatusRequestTimeout:
            return "Request Timeout";
        case StatusConflict:
            return "Conflict";
        case StatusGone:
            return "Gone";
        case StatusLengthRequired:
            return "Length Required";
        case StatusPreconditionFailed:
            return "Precondition Failed";
        case StatusRequestEntityTooLarge:
            return "Request Entity Too Large";
        case StatusRequestURITooLong:
            return "Request URI Too Long";
        case StatusUnsupportedMediaType:
            return "Unsupported Media Type";
        case StatusRequestedRangeNotSatisfiable:
            return "Requested Range Not Satisfiable";
        case StatusExpectationFailed:
            return "Expectation Failed";
        case StatusTeapot:
            return "I'm a teapot";
        case StatusMisdirectedRequest:
            return "Misdirected Request";
        case StatusUnprocessableEntity:
            return "Unprocessable Entity";
        case StatusLocked:
            return "Locked";
        case StatusFailedDependency:
            return "Failed Dependency";
        case StatusTooEarly:
            return "Too Early";
        case StatusUpgradeRequired:
            return "Upgrade Required";
        case StatusPreconditionRequired:
            return "Precondition Required";
        case StatusTooManyRequests:
            return "Too Many Requests";
        case StatusRequestHeaderFieldsTooLarge:
            return "Request Header Fields Too Large";
        case StatusUnavailableForLegalReasons:
            return "Unavailable For Legal Reasons";
        case StatusInternalServerError:
            return "Internal Server Error";
        case StatusNotImplemented:
            return "Not Implemented";
        case StatusBadGateway:
            return "Bad Gateway";
        case StatusServiceUnavailable:
            return "Service Unavailable";
        case StatusGatewayTimeout:
            return "Gateway Timeout";
        case StatusHTTPVersionNotSupported:
            return "HTTP Version Not Supported";
        case StatusVariantAlsoNegotiates:
            return "Variant Also Negotiates";
        case StatusInsufficientStorage:
            return "Insufficient Storage";
        case StatusLoopDetected:
            return "Loop Detected";
        case StatusNotExtended:
            return "Not Extended";
        case StatusNetworkAuthenticationRequired:
            return "Network Authentication Required";
        default:
            return "";
    }
}
