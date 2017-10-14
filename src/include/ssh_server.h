#ifndef __SSH_SERVER_H__
#define __SSH_SERVER_H__
#include <pthread.h>
#include <semaphore.h>

#define MAX_PATH 128
#define MAX_THREADS 20

// A variable of this structure contains data that is available to all threads
struct SSH_DATA {
	bool alive;
	bool reboot_on_exit;
	char host_keys_folder[MAX_PATH];
	char auth_keys_folder[MAX_PATH];
	unsigned int port;
	int verbosity;
	sem_t thread_list;
	ssh_bind sshbind;
	bool ssh_disconnect;
};

int run_sshserver( struct SSH_DATA *);
#endif // __SSH_SERVER_H__
