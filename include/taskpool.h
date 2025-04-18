#ifndef TASKPOOL_H
#define TASKPOOL_H

#include <solidc/larena.h>

typedef struct {
    int epoll_fd;   // Epoll file descriptor
    int client_fd;  // Client file descriptor
    LArena* arena;  // task arena
} Task;

// Initialize the task pool
void taskpool_init(void);

// Get a free task from the pool. No need to syncronise because the event loop
// runs only in main thread.
Task* taskpool_get(void);

// Put a task back into the pool and reset its arena.
void taskpool_put(Task* task);

// Free all tasks in the pool
// and destroy their arenas.
void taskpool_destroy(void);

#endif /* TASKPOOL_H */
