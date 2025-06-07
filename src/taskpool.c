#include <assert.h>
#include <pthread.h>

#include "../include/constants.h"
#include "../include/logging.h"
#include "../include/taskpool.h"

#define TASK_CAPACITY (MAXEVENTS)
static Task taskPool[TASK_CAPACITY];
static int freeList[TASK_CAPACITY];    // Stack of free indices
static int freeCount             = 0;  // Number of free tasks
static pthread_mutex_t poolMutex = PTHREAD_MUTEX_INITIALIZER;

void taskpool_init(void) {
    pthread_mutex_lock(&poolMutex);
    // Initialize all tasks
    for (int i = 0; i < TASK_CAPACITY; i++) {
        taskPool[i].client_fd = -1;
        taskPool[i].epoll_fd  = -1;
        // Add to free list (in reverse order for better cache locality)
        freeList[i] = TASK_CAPACITY - 1 - i;
    }
    freeCount = TASK_CAPACITY;
    pthread_mutex_unlock(&poolMutex);
}

Task* taskpool_get(void) {
    pthread_mutex_lock(&poolMutex);
    if (freeCount == 0) {
        pthread_mutex_unlock(&poolMutex);
        return NULL;  // No free tasks
    }

    // Pop from free list - O(1) operation
    int index  = freeList[--freeCount];
    Task* task = &taskPool[index];

    // Task should already be reset, but double-check in debug builds
    assert(task->client_fd == -1);

    // Mark as in-use (though the fd is already -1 from reset)
    pthread_mutex_unlock(&poolMutex);
    return task;
}

void taskpool_put(Task* task) {
    // Reset task state
    task->client_fd = -1;
    task->epoll_fd  = -1;

    pthread_mutex_lock(&poolMutex);
    // Add back to free list - O(1) operation
    int index = task - taskPool;  // Calculate index from pointer

    assert(index >= 0 && index < TASK_CAPACITY);
    assert(freeCount < TASK_CAPACITY);

    freeList[freeCount++] = index;
    pthread_mutex_unlock(&poolMutex);
}

void taskpool_destroy(void) {
    pthread_mutex_destroy(&poolMutex);
}
