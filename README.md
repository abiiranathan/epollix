# async-servers-in-c

Experiments with modern asynchronous servers in C using epoll and select.

In this experiment, I attempt to write an asyncronous epoll web server capable of handling
20,000 requests/sec with a threadpool of a couple threads.

This is a learning experience and SHOULD NOT BE USE in production.
