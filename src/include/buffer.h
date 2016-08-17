#ifndef __buffer_h__
#define __buffer_h__
#include <pthread.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#define INITIAL_BUFSIZE 2048

typedef struct _process_buffer_struct {
	char *buf;                 // can be modified inside called routine
	size_t buf_size;           // can be modified inside called routine
	size_t size_used;          // unmodified inside called routine
	pthread_mutex_t *sdk_lock; // will be modified by called routine
	bool verify_handshake;     // not modified by called routine
	bool *exit_called;         // can be modified inside called routine
	ssh_channel chan;         // unchanged in called routine
} process_buf_struct;

// process_buffer char* buf parameter holds the inbound buffer and will
// contain the outbound buffer on return, if no error.
// buf_size is the size of the buffer while size_used is the number of bytes
// the buffer is currently using.
//
// A positive return value indicates the number of bytes used in the return
// buffer. A negative value indicates an error.  Since we always send an
// ACK or NACK handshake we are always sending data, or have an error,
// therefore we should never return a value 0.
int process_buffer( process_buf_struct * buf_struct);

#endif //__buffer_h__
