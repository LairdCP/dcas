#ifndef __buffer_h__
#define __buffer_h__
#include <pthread.h>

#define BUFSIZE 2048

//processbufer requires a pointer to a buffer of size BUFSIZE
//the passed in buffer will be reused for the data to be sent with the
//size as the return value. A 0 return value means there is no data
//to send back, while a negative value indicates error
int processbuff(char * buf, size_t size, pthread_mutex_t *sdk_lock);

#endif //__buffer_h__
