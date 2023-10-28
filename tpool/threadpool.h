#ifndef THREADPOOL_H
#define THREADPOOL_H

typedef struct ThreadPool ThreadPool;

ThreadPool* threadpool_create(int num_threads);
void threadpool_destroy(ThreadPool* pool);
int threadpool_add_task(ThreadPool* pool, void (*task)(void*), void* arg);
void threadpool_wait(ThreadPool* pool);

#endif /* THREADPOOL_H */
