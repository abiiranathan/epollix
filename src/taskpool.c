#include "../include/taskpool.h"
#include "../include/constants.h"
#include "../include/logging.h"

#define TASK_CAPACITY (MAXEVENTS / 2)
static Task taskPool[TASK_CAPACITY];

void taskpool_init(void) {
    for (int i = 0; i < TASK_CAPACITY; i++) {
        taskPool[i].client_fd = -1;
        taskPool[i].epoll_fd  = -1;
        taskPool[i].arena     = arena_create(PER_REQUEST_ARENA_MEM);
        LOG_ASSERT(taskPool[i].arena, "error allocating arena");
    }
}

Task* taskpool_get(void) {
    for (int i = 0; i < TASK_CAPACITY; i++) {
        if (taskPool[i].client_fd == -1) {
            return &taskPool[i];
        }
    }
    return NULL;
}

void taskpool_put(Task* task) {
    task->client_fd = -1;
    task->epoll_fd  = -1;
    arena_reset(task->arena);
}

void taskpool_destroy(void) {
    for (int i = 0; i < TASK_CAPACITY; i++) {
        if (taskPool[i].client_fd == -1) {
            arena_destroy(taskPool[i].arena);
        }
    }
}
