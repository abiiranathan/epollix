# epollix

Robust web server written in C using epoll.

Warning: This is a work in progress and possibly not yet fit for production use.
It's API is going to change. That said, give it a try and report bugs!

## Features
- [x] Robust HTTP server with epoll.
- [x] Efficient static file serving with chunked transfer with `sendfile` unix function.
- [x] Routing with parameter parsing and query string parsing(regex not supported yet)
- [x] Form processing(application/x-www-form-urlencoded + multipart/form-data that supports multiple file uploads).
- [x] Appropriate error handling
- [x] Support for range requests( making it easy to stream videos and audio files)
- [x] Very fast and efficient, uses epoll for event handling. Consumes ~= 5 MB of memory for > 1,000,000 concurrent connections and < 15% CPU usage.

No support for windows yet.

## Big missing features
- [ ] Support for keep-alive connections
- [ ] Support for binary files in multipart/form-data
- [ ] Support for cookies
- [ ] Support for sessions
- [ ] Middleware support
- [ ] HTTPS support
- [ ] Websocket support
- [ ] Better project structure and refactoring
- [ ] Tests for all features

## How to run

```bash
make
./bin/server 8000
```

Check for memory leaks:

```bash
make check
```

Dependencies:
- solidc: A personal C library for common data structures and utilities that are cross-platform and easy to use. [Find solidc on Github](https://github.com/abiiranathan/solidc)

Install solidc:

Requires cmake and make to be installed. You may also require the Ninja build system.

```bash
git clone https://github.com/abiiranathan/solidc.git
cd solidc
mkdir -p build
cd build
cmake ..
make
sudo cmake --install .
```

### Benchmarks with ab( Apache Benchmark)
```bash
ab -n 1000000 -c 100 http://localhost:8000/
```

Running the above command will send 1000000 requests with 100 concurrent connections to the server running on localhost:8000. The server should be able to handle this load without any issues.

Results when compiled with -O3 flag:

```bash
ab -n 1000000 -c 100 http://localhost:8000/
This is ApacheBench, Version 2.3 <$Revision: 1913912 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking localhost (be patient)
Completed 100000 requests
Completed 200000 requests
Completed 300000 requests
Completed 400000 requests
Completed 500000 requests
Completed 600000 requests
Completed 700000 requests
Completed 800000 requests
Completed 900000 requests
Completed 1000000 requests
Finished 1000000 requests


Server Software:        
Server Hostname:        localhost
Server Port:            8000

Document Path:          /
Document Length:        1800 bytes

Concurrency Level:      100
Time taken for tests:   38.653 seconds
Complete requests:      1000000
Failed requests:        0
Total transferred:      1908000000 bytes
HTML transferred:       1800000000 bytes
Requests per second:    25870.95 [#/sec] (mean)
Time per request:       3.865 [ms] (mean)
Time per request:       0.039 [ms] (mean, across all concurrent requests)
Transfer rate:          48204.85 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    2   0.4      2       8
Processing:     0    2   0.5      2      24
Waiting:        0    1   0.4      1      24
Total:          3    4   0.6      4      25

Percentage of the requests served within a certain time (ms)
  50%      4
  66%      4
  75%      4
  80%      4
  90%      4
  95%      5
  98%      5
  99%      6
 100%     25 (longest request)
```

License: MIT

