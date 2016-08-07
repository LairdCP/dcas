#ifndef __buffer_h__
#define __buffer_h__
#include <pthread.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#define BUFSIZE 2048

//process_buffer Char* buf parameter holds the inbound buffer and will
//contain the outbound buffer on return, if no error.
//buf_size is the size of the buffer while nbytes is the number of bytes
//the buffer is currently using.  A positive return value indicates the
//number of bytes used in the return buffer. A negative value indicates
//an error.  Since we always send an ACK or NACK if no unrecoverable error,
//we should never return a value 0.
int process_buffer(char * buf, size_t buf_size, size_t nbytes,
                   pthread_mutex_t *sdk_lock, bool must_be_handshake,
                   bool *exit_called, ssh_channel chan);

#endif //__buffer_h__
