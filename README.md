# epollix

Robust web server written in C using epoll.

Warning: This is a work in progress and possibly not yet fit for production use.
It's API is going to change. That said, give it a try and report bugs!

## Features
- [x] Robust HTTP server with epoll.
- [x] Efficient static file serving with chunked transfer with `sendfile` unix function.
- [x] Routing with parameter parsing and query string parsing(regex not supported yet)
- [x] Support for route groups.
- [x] Form processing(application/x-www-form-urlencoded + multipart/form-data that supports multiple file uploads).
- [x] Support for binary files in multipart/form-data
- [x] Support for range requests( making it easy to stream videos and audio files)
- [x] Very fast (30K - 40K req/sec on 2 threads) and efficient, uses epoll for event handling. Consumes ~= 5 MB of memory for > 1,000,000 concurrent connections and < 15% CPU usage.
- [x] Robust Middleware support at route, group, and application level.
- [x] CMAKE integration
- [x] Use of `solidc` library for common data structures and utilities.
 
## Utilities
- [x] `epollix` comes with a simple and easy to use logger middleware, BasicAuth middleware, and BearerAuth middleware using JWT.
- [x] `epollix` has a crypto module that supports hashing, encryption, base64 encoding and decoding and decryption using openssl and libsodium.
- [x] Support for gzip compression and decompression using zlib. Both static files and dynamic responses can be compressed.

> No support for windows yet. Honestly, I don't know how to implement epoll on windows. If you know how to do it, please let me know.

## Big missing features
- [ ] Support for keep-alive connections
- [ ] Support for cookies
- [ ] Support for sessions
- [ ] HTTPS support
- [ ] Websocket support
- [ ] Tests for all features

## Tested modules (see tests directory)
- [x] crypto
- [x] gzip
- [x] mime
- [x] epollix (web server): header parsing, query and parameter parsing, form processing.
More tests are added as the library grows.

## Installation

See below for instructions on how to install the solidc dependency.

```bash
git clone https://github.com/abiiranathan/epollix.git
cd epollix
make
```

### Dependencies
- **solidc**: A personal C library for common data structures and utilities that are cross-platform and easy to use. [Find solidc on Github](https://github.com/abiiranathan/solidc)

### Optional dependencies
- **cipherkit**: A personal C library for cryptographic functions, hashing etc. [Find solidc on Github](https://github.com/abiiranathan/cipherkit)

The middleware and example are only built if the optional dependencies are found. If you want to build the middleware and example, you need to clone the `cipherkit` repository and build it. Not that it also depends on OpenSSL, libsodium, zlib, cjson.

Find the installation instructions for `cipherkit` from the link above.

```bash
git clone https://github.com/abiiranathan/cipherkit.git
cd cipherkit
sudo make install
```

## Run the example
After building the library, you can run the example server by running the following commands:

```bash
cd example

# default port 3000.
../build/example/example
```

## Public API Reference

The public API is defined in the `include/epollix.h` header file. The API is well documented with comments. You can find the API reference in the [docs](./docs) directory.

[Read the docs here](docs/epollix.md)

## License
MIT

