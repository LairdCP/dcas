#define _POSIX_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#define __USE_POSIX199309
#include <time.h>

#include "debug.h"
#include "buffer.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include "ssh_server.h"

#define SSHD_USER "libssh"
#define SSHD_PASSWORD "libssh"

typedef struct LIST_T {
	pthread_t data;
	struct LIST_T * next;
} list_t;

// completed thread structure
struct THREAD_LIST{
	list_t *head;
	pthread_mutex_t lock;
};

struct DISPATCH_DATA {
	ssh_session session;
	bool *alive;
	bool *exit_called;
	pthread_mutex_t sdk_lock;
	sem_t thread_init; // used between dispatcher and thread to know when
	                   // safe to reuse dispatcher's stack variable
	sem_t *thread_list;// used to limit total active threads
	struct THREAD_LIST completed;
};

#define DUMP_LOCATION printf("%s\t%s:%d\n",__FILE__,__func__,__LINE__);

// when a thread completes, it calls this routine so that it's thread ID
// can be queued.  At a later point, the list will be emptied and the
// thread's resources will be recovered by a pthread_join() call
void add_thread_to_completed_list( struct THREAD_LIST *completed, pthread_t data)
{
	pthread_mutex_lock(&completed->lock);
	list_t * curr = completed->head;
	list_t * last = NULL;
	while(curr) {
		last = curr;
		curr = curr->next;
	}
	curr = (list_t *)malloc(sizeof(list_t));
	curr->data = data;
	curr->next = NULL;

	if (!completed->head)
		completed->head = curr;
	else
		last->next = curr;

	pthread_mutex_unlock(&completed->lock);
}

// This is called from the dispatch routine of the main thread which
// could be blocked waiting for a connection when a thread ends.  This
// allows us to clean up threads that have completed at a later time.
void empty_completed_thread_list( struct THREAD_LIST *completed)
{
	assert(completed);
	pthread_mutex_lock(&completed->lock);
	list_t * curr = completed->head;
	list_t * next = NULL;
	while (curr) {
		pthread_join(curr->data, NULL );
		next = curr->next;
		free(curr);
		curr=next;
	}
	completed->head = NULL;
	pthread_mutex_unlock(&completed->lock);
}

static int auth_password(const char *user, const char *password)
{
	if(strcmp(user, SSHD_USER))
		return 0;
	if(strcmp(password, SSHD_PASSWORD))
		return 0;
	return 1; // authenticated
}

static int authenticate(ssh_session session)
{
	ssh_message message;

	do {
		message=ssh_message_get(session);
		if(!message)
			break;
		switch(ssh_message_type(message)) {
		case SSH_REQUEST_AUTH:
			switch(ssh_message_subtype(message)) {
			case SSH_AUTH_METHOD_PASSWORD:
				DBGINFO("User %s wants to auth with pass %s\n",
				       ssh_message_auth_user(message),
				       ssh_message_auth_password(message));
				if(auth_password(ssh_message_auth_user(message),
				                 ssh_message_auth_password(message))) {
					ssh_message_auth_reply_success(message,0);
					ssh_message_free(message);
					return 1;
				}
				ssh_message_auth_set_methods(message,
				                             SSH_AUTH_METHOD_PASSWORD |
				                             SSH_AUTH_METHOD_INTERACTIVE);
				// not authenticated, send default message
				ssh_message_reply_default(message);
				break;
			case SSH_AUTH_METHOD_NONE:
			default:
				DBGINFO("User %s wants to auth with unknown auth %d\n",
				       ssh_message_auth_user(message),
				       ssh_message_subtype(message));
				ssh_message_auth_set_methods(message,
				                             SSH_AUTH_METHOD_PASSWORD);
				ssh_message_reply_default(message);
				break;
			}
			break;
		default:
			ssh_message_auth_set_methods(message,
			                             SSH_AUTH_METHOD_PASSWORD);
			ssh_message_reply_default(message);
		}
		ssh_message_free(message);
	} while (1);
	return 0;
}

void * ssh_session_thread( void *param )
{
	ssh_message message;
	process_buf_struct buf_struct = {0};
	ssh_channel chan=0;
	int nbytes, auth=0;
	struct DISPATCH_DATA *dispatch_data = (struct DISPATCH_DATA*)param;
	bool *alive;
	ssh_session session;
	size_t nwritten, *const buf_size = &buf_struct.buf_size;
	char **const buf = &buf_struct.buf;

	alive = dispatch_data->alive;     //read only. Only set by dispatch or signal catch
	session = dispatch_data->session; //we will be responsible for session now
	dispatch_data->session = NULL;    //ensure no other thread points to this
	sem_post(&dispatch_data->thread_init);  // signal dispatch routine thread
	                                        // that we've copied the pointer
	                                        // from it's stack data

	buf_struct.buf = malloc(INITIAL_BUFSIZE);
	buf_struct.buf_size = INITIAL_BUFSIZE;
	buf_struct.exit_called = dispatch_data->exit_called;
	buf_struct.sdk_lock = &dispatch_data->sdk_lock;
	buf_struct.verify_handshake = true;

	if (ssh_handle_key_exchange(session)) {
		DBGERROR("Error: ssh_void handle_key_exchange: %s\n", ssh_get_error(session));
		goto exit_session;
	}

	if(*buf==NULL) {
		DBGERROR("Error: Unable to malloc buffer size:%d\n", INITIAL_BUFSIZE);
		goto exit_session;
	}

	/* proceed to authentication */
	auth = authenticate(session);
	if(!auth) {
		DBGERROR("Authentication error: %s\n", ssh_get_error(session));
		goto exit_disconnect;
	}

	DBGINFO("**** Successful connection\n");
	/* wait for a channel session */
	do {
		message = ssh_message_get(session);
		if(message) {
			if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
			    ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
				chan = ssh_message_channel_request_open_reply_accept(message);
				buf_struct.chan = chan;
				ssh_message_free(message);
				break;
			} else {
				ssh_message_reply_default(message);
				ssh_message_free(message);
			}
		} else {
			break;
		}
	} while(!chan && *alive);

	if(!*alive) {
		DBGINFO("Alive indicator has been disabled\n");
		goto exit_channel;
	}

	if(!chan) {
		DBGERROR("Error: client did not ask for a channel session (%s)\n",
		       ssh_get_error(session));
		goto exit_disconnect;
	}

	DBGDEBUG("Client connected!\n");

	int extra;
	do {
		nbytes=ssh_channel_read(chan,*buf, *buf_size, 0);
		if(nbytes >0)
		while ((extra=ssh_channel_poll(chan, 0)) > 0) {
			char * tmp = realloc(*buf, *buf_size+extra);

			if (!tmp){
				DBGERROR("Error: could not realloc buffer size\n");
				goto exit_channel;
			}

			DBGINFO(" buffer size increased by %d for channel read\n", extra);

			// store modified memory pointer
			*buf = tmp;

			// move tmp to start of extended space
			tmp = *buf+*buf_size;

			*buf_size += extra;

			// read into extra space of buff up to extra number of characters
			extra = ssh_channel_read(chan,tmp, extra, 0);
			if (extra > 0)
				nbytes += extra;
			else {
				// either EOF or error
				nbytes = 0;
				break;
			}
		}

		if(nbytes>0) {
			DBGINFO("Got %d bytes from client:\n", nbytes);

			buf_struct.size_used = nbytes;
			nbytes = process_buffer(&buf_struct);

			if (nbytes<0){
				DBGERROR("error in process_bufer(): %d\n", nbytes);
				goto exit_channel;
			}
			if (nbytes==0){
				DBGINFO("no command received - no outbound buffer\n");//no-op
			}
			else{
				nwritten = ssh_channel_write(chan,*buf, nbytes);
				DBGINFO("Wrote %zu bytes\n", nwritten);
				if (nwritten != nbytes){
					DBGERROR("Failure to send buffer\n");
					goto exit_channel;
				}
				buf_struct.verify_handshake = false;
			}
		}
		if ((nbytes==SSH_AGAIN) && (*alive))
			continue;
	} while ((nbytes>0) && (*alive));

	if (*buf_struct.exit_called)
		DBGINFO("system restart requested\n");
	else
		DBGDEBUG("Read thread exiting due to EOF on channel\n");

exit_channel:
	if (chan)
		ssh_channel_close(chan);
exit_disconnect:
	ssh_disconnect(session);
exit_session:
	ssh_free(session);
	session = NULL;
	if(buf_struct.buf)
		free(buf_struct.buf);

	add_thread_to_completed_list( &dispatch_data->completed,
	                               pthread_self());
	sem_post(dispatch_data->thread_list);
	if (*buf_struct.exit_called)
		kill(getpid(), SIGINT);
	DBGDEBUG("thread exiting\n");
	return NULL;
}

int check_with_timeout( int return_value, int test_value,
                        int * remaining, struct timespec *sleep_time)
{
	if ((return_value==0)                  //worked
	     || (*remaining==0)                //time has expired
	     || (test_value != return_value))  //error other then what we are testing for
		return 0;

	(*remaining)--;
	nanosleep(sleep_time, NULL);
	return 1;
}

int run_sshserver( struct SSH_DATA *ssh_data )
{
	ssh_bind *sshbind = &ssh_data->sshbind;
	int i,r;
	char key_tmp[MAX_PATH];
	pthread_t child;
	struct timespec sleep_duration;
	struct DISPATCH_DATA dispatch_data = {0};

	i = 10;
	sleep_duration.tv_sec =0;
	sleep_duration.tv_nsec = 10000000; // 10 ms

	while( check_with_timeout (r=pthread_mutex_init(&dispatch_data.sdk_lock,NULL),
	                           EAGAIN, &i, &sleep_duration));
	if (r)
	{
		DBGERROR("Mutex init failed with: %s\n", strerror(errno));
		return 1;
	}

	i=10;
	while( check_with_timeout (r=pthread_mutex_init(&dispatch_data.completed.lock,NULL),
	                           EAGAIN, &i, &sleep_duration));
	if (r)
	{
		DBGERROR("Mutex init failed with: %s\n", strerror(errno));
		return 1;
	}

	dispatch_data.alive = &ssh_data->alive;
	dispatch_data.exit_called = &ssh_data->reboot_on_exit;

	dispatch_data.thread_list = &ssh_data->thread_list;
	dispatch_data.completed.head = NULL;

	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();

	*sshbind=ssh_bind_new();


	ssh_bind_options_set(*sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &(ssh_data->verbosity));
	ssh_bind_options_set(*sshbind, SSH_BIND_OPTIONS_BINDPORT, &(ssh_data->port));

	strncpy(key_tmp, ssh_data->keys_folder, MAX_PATH);
	strncat(key_tmp, "/ssh_host_dsa_key", MAX_PATH);
	ssh_bind_options_set(*sshbind, SSH_BIND_OPTIONS_DSAKEY, key_tmp );
	strncpy(key_tmp, ssh_data->keys_folder, MAX_PATH);
	strncat(key_tmp, "/ssh_host_rsa_key", MAX_PATH);
	ssh_bind_options_set(*sshbind, SSH_BIND_OPTIONS_RSAKEY, key_tmp);

	if(ssh_bind_listen(*sshbind)<0) {
		DBGERROR("Error listening to socket: %s\n", ssh_get_error(*sshbind));
		r = 1;
		goto cleanup;
	}
	DBGINFO("Started DCAS on port %d\n", ssh_data->port);

	while (ssh_data->alive)
	{
		sem_wait(dispatch_data.thread_list); // this semaphore is initialized
		                                     // to MAX_THREADS and ensures that
		                                     // we adhere to that limit
		if (!ssh_data->alive)
			break;

		empty_completed_thread_list(&dispatch_data.completed);

		dispatch_data.session = ssh_new();
		r = ssh_bind_accept(*sshbind, dispatch_data.session);

		if(r==SSH_ERROR) {
			//TODO - determine if we should stay running or exit the application
			if (ssh_data->alive)
				DBGERROR("Error accepting a connection: %s\n", ssh_get_error(*sshbind));
			ssh_free(dispatch_data.session);
			dispatch_data.session = NULL;
			continue;
		}
		i = 10;
		while (check_with_timeout (r=pthread_create(&child, NULL,
		                                            &ssh_session_thread, &dispatch_data),
		                            EAGAIN, &i, &sleep_duration));
		if (r) {
			DBGERROR("Unable to start child thread: %s\n", strerror(r));
			ssh_data->alive = false; // kill any children
			ssh_free(dispatch_data.session);
			r=1;
			break; // abort while loop
		}
		sem_wait(&dispatch_data.thread_init); // wait for child to copy data from stack
	}

	empty_completed_thread_list(&dispatch_data.completed);

cleanup:
		ssh_bind_free(*sshbind);
	ssh_finalize();
	pthread_mutex_destroy(&(dispatch_data.sdk_lock));
	pthread_mutex_destroy(&dispatch_data.completed.lock);

	if (*dispatch_data.exit_called){
		// call system's reboot command rather then reboot API directly as the system version may do additional syncing.
		//TODO - we may only want to support this on WBs rather then all
		printf("***** calling reboot *****\n");
		system("reboot");
	}
	return r;
}
