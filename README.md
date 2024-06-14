# epollix

An ambitious project to create a web server using epoll in C.

## Features
- [x] Basic HTTP server
- [x] Static file serving
- [x] Routing with parameter parsing and query string parsing(regex not supported yet)
- [x] Form processing(application/x-www-form-urlencoded + multipart/form-data(Only plain text for now))
- [x] Appropriate error handling
- [x] Support for range requests( making it easy to stream videos and audio files)
- [x] Very fast and efficient, uses epoll for event handling. Consumes < 10 MB of memory for > 100000 concurrent connections and < 10% CPU usage.

## Big missing features
- [ ] Support for keep-alive connections
- [ ] Regex support for routing
- [ ] Support for binary files in multipart/form-data
- [ ] Support for cookies
- [ ] Support for sessions
- [ ] Middleware support
- [ ] HTTPS support
- [ ] Websocket support
- [ ] Better project structure and refactoring
- [ ] Tests for all features

Known issues:
We can improve the performance of the server by not using `EPOLLONESHOT` flag. This flag is used to make sure that the same file descriptor is not added to the epoll queue multiple times. The problem is that without it, you need to keep state for each file descriptor and that is not possible with the current design. If we can find a way to keep state for each file descriptor, we can remove this flag and improve the performance of the server.

## How to run

```bash
make
./bin/server 8080
```

## How to test

```bash
make test
```

Check for memory leaks:

```bash
make check
```

Dependencies:
- solidc: A personal C library for common data structures and utilities that are cross-platform and easy to use. [Find solidc on Github](https://github.com/abiiranathan/solidc)
- libcurl: For url parsing
- libmagic: For mime type detection

Installing dependencies:

Ubuntu or Debian:
```bash
sudo apt-get install libcurl4-openssl-dev libmagic-dev
```

Arch Linux:

```bash
sudo pacman -S curl file
```

Verify the installation:

```bash
curl --version
file --version
```

Install solidc:

Required cmake and make to be installed. You may also require Ninja build system.

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
ab -n 1000000 -c 1000 http://localhost:8080/
```
Running the above command will send 1000000 requests with 1000 concurrent connections to the server running on localhost:8080. The server should be able to handle this load without any issues.

Results when compiled with -O3 flag:

```bash
ab -n 1000000 -c 100 http://localhost:8080/ 
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
Server Port:            8080

Document Path:          /
Document Length:        36 bytes

Concurrency Level:      100
Time taken for tests:   31.480 seconds
Complete requests:      1000000
Failed requests:        0
Total transferred:      100000000 bytes
HTML transferred:       36000000 bytes
Requests per second:    31766.53 [#/sec] (mean)
Time per request:       3.148 [ms] (mean)
Time per request:       0.031 [ms] (mean, across all concurrent requests)
Transfer rate:          3102.20 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    1   0.3      1       5
Processing:     0    2   0.3      2       6
Waiting:        0    1   0.3      2       5
Total:          2    3   0.4      3       7

Percentage of the requests served within a certain time (ms)
  50%      3
  66%      3
  75%      3
  80%      3
  90%      4
  95%      4
  98%      4
  99%      4
 100%      7 (longest request)


```

### Using wrk:

```bash
wrk -c 5 -d 15 -T 5000 -H "Host: localhost:8080" --timeout=1000 http://localhost:8080

Running 15s test @ http://localhost:8080
  2 threads and 5 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    63.62us   31.34us   2.70ms   92.58%
    Req/Sec    16.99k   772.59    19.10k    64.57%
  510375 requests in 15.10s, 48.67MB read
  Socket errors: connect 0, read 510375, write 0, timeout 0
Requests/sec:  33800.44
Transfer/sec:      3.22MB
```

License: MIT

