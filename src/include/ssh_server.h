#ifndef __SSH_SERVER_H__
#define __SSH_SERVER_H__
#include <pthread.h>

#define MAX_PATH 128

struct SSH_DATA {
	bool alive;
	char keys_folder[MAX_PATH];
	unsigned int port;
	int verbosity;
};

#endif // __SSH_SERVER_H__
