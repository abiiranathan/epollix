#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct Task {
  void (*function)(void*);
  void* arg;
  struct Task* next;
} Task;

typedef struct ThreadPool {
  pthread_mutex_t lock;
  pthread_cond_t task_available;
  pthread_cond_t all_tasks_completed;
  Task* task_queue;
  int num_threads;
  int num_working_threads;
  bool shutdown;
} ThreadPool;

static void* worker_thread(void* arg) {
  ThreadPool* pool = (ThreadPool*)arg;

  while (true) {
    pthread_mutex_lock(&pool->lock);

    // Wait until there is a task in the queue or the pool is shutting down
    while (pool->task_queue == NULL && !pool->shutdown) {
      pthread_cond_wait(&pool->task_available, &pool->lock);
    }

    if (pool->shutdown) {
      pthread_mutex_unlock(&pool->lock);
      pthread_exit(NULL);
    }

    Task* task = pool->task_queue;
    if (task != NULL) {
      // Remove the task from the queue
      pool->task_queue = task->next;

      // Increment the number of working threads
      pool->num_working_threads++;

      // Unlock the pool
      pthread_mutex_unlock(&pool->lock);

      // Execute the task
      task->function(task->arg);

      // Free the task memory
      free(task);

      // Decrement the number of working threads
      pthread_mutex_lock(&pool->lock);
      pool->num_working_threads--;

      // Signal that a task has completed
      if (pool->num_working_threads == 0) {
        pthread_cond_signal(&pool->all_tasks_completed);
      }

      pthread_mutex_unlock(&pool->lock);
    } else {
      pthread_mutex_unlock(&pool->lock);
      pthread_exit(NULL);
    }
  }

  pthread_exit(NULL);
}

ThreadPool* threadpool_create(int num_threads) {
  if (num_threads <= 0) {
    printf("num_threads must be > 0");
    return NULL;
  }

  ThreadPool* pool = (ThreadPool*)malloc(sizeof(ThreadPool));
  if (pool == NULL) {
    perror("malloc");
    return NULL;
  }

  pthread_mutex_init(&pool->lock, NULL);
  pthread_cond_init(&pool->task_available, NULL);
  pthread_cond_init(&pool->all_tasks_completed, NULL);

  pool->task_queue          = NULL;
  pool->num_threads         = num_threads;
  pool->num_working_threads = 0;
  pool->shutdown            = false;

  // Create worker threads
  for (int i = 0; i < num_threads; i++) {
    pthread_t thread;
    pthread_create(&thread, NULL, worker_thread, (void*)pool);
    pthread_detach(thread);
  }

  return pool;
}

void threadpool_destroy(ThreadPool* pool) {
  if (pool == NULL) {
    return;
  }

  pthread_mutex_lock(&pool->lock);
  pool->shutdown = true;
  pthread_mutex_unlock(&pool->lock);

  pthread_cond_broadcast(&pool->task_available);

  pthread_mutex_lock(&pool->lock);
  while (pool->num_working_threads > 0) {
    pthread_cond_wait(&pool->all_tasks_completed, &pool->lock);
  }

  pthread_mutex_unlock(&pool->lock);

  pthread_mutex_destroy(&pool->lock);
  pthread_cond_destroy(&pool->task_available);
  pthread_cond_destroy(&pool->all_tasks_completed);

  free(pool);
}

int threadpool_add_task(ThreadPool* pool, void (*task)(void*), void* arg) {
  if (pool == NULL || task == NULL) {
    return -1;
  }

  Task* new_task = (Task*)malloc(sizeof(Task));
  if (new_task == NULL) {
    return -1;
  }

  new_task->function = task;
  new_task->arg      = arg;
  new_task->next     = NULL;

  pthread_mutex_lock(&pool->lock);

  // Add the new task to the end of the task queue
  if (pool->task_queue == NULL) {
    pool->task_queue = new_task;
  } else {
    Task* current_task = pool->task_queue;
    while (current_task->next != NULL) {
      current_task = current_task->next;
    }
    current_task->next = new_task;
  }

  // Signal that a new task is available
  pthread_cond_signal(&pool->task_available);

  pthread_mutex_unlock(&pool->lock);

  return 0;
}

void threadpool_wait(ThreadPool* pool) {
  pthread_mutex_lock(&pool->lock);
  while (pool->task_queue != NULL || pool->num_working_threads > 0) {
    pthread_cond_wait(&pool->all_tasks_completed, &pool->lock);
  }
  pthread_mutex_unlock(&pool->lock);
}
