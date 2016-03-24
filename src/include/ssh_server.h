#ifndef __SSH_SERVER_H__
#define __SSH_SERVER_H__
#include <pthread.h>
#include <semaphore.h>

#define MAX_PATH 128
#define MAX_THREADS 20

struct SSH_DATA {
	bool alive;
	char keys_folder[MAX_PATH];
	unsigned int port;
	int verbosity;
	sem_t thread_list;
};

#endif // __SSH_SERVER_H__
