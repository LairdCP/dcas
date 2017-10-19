#define _POSIX_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#define __USE_POSIX199309
#include <time.h>

#include "debug.h"
#include "buffer.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <sdc_sdk.h>
#include "ssh_server.h"

typedef struct LIST_T {
	pthread_t data;
	struct LIST_T * next;
} list_t;

// completed thread structure
struct THREAD_LIST{
	list_t *head;
	pthread_mutex_t lock;
};

// the authentication process is single threaded so a variable of this type can be reused for each auth.
struct AUTH_DATA {
	int auth;
	int auth_error;
	int attempts; // used for password auth
	ssh_channel *chan; // *chan is a reference pointer and the creating/free is handled outside of this reference
	struct SSH_DATA *ssh_data;
};

struct DISPATCH_DATA {
	ssh_session session;
	bool *alive;
	bool *exit_called;
	pthread_mutex_t sdk_lock; // SDK is not multithread safe. 
	pthread_mutex_t auth_lock;  // allow one authentication at a time - simplifies sharing of cb data
	sem_t thread_init; // used between dispatcher and thread to know when
	                   // safe to reuse dispatcher's stack variable
	sem_t *thread_list;// used to limit total active threads
	struct THREAD_LIST completed;
	struct AUTH_DATA * auth_data;
	struct SSH_DATA *ssh_data;
	sem_t auth_clients_sem;
};

#define DUMP_LOCATION printf("%s\t%s:%d\n",__FILE__,__func__,__LINE__);

// - Authentication functions
int auth_password (ssh_session session, const char *user,
                                        const char *password,
                                        void *userdata)
{
	struct AUTH_DATA *auth_data = (struct AUTH_DATA*) userdata;
	DBGINFO("%s: Authenticating user ->%s<-\n", __func__, user);
	auth_data->auth = auth_data->auth_error = 0;
	if(auth_data->attempts++ >= 3){
		DBGINFO("Max Attempts reached\n");
		auth_data->auth_error=1;
		return SSH_AUTH_DENIED;
	}
	if(strncmp(user, auth_data->ssh_data->username, MAX_USER))
		return SSH_AUTH_DENIED;
	if(strncmp(password, auth_data->ssh_data->password, MAX_PASSWORD))
		return SSH_AUTH_DENIED;
	auth_data->auth = 1;
	return SSH_AUTH_SUCCESS; // authenticated
}

int auth_publickey(ssh_session session, const char *user,
                                        struct ssh_key_struct *pubkey,
                                        char signature_state,
                                        void *userdata)
{
	struct AUTH_DATA *auth_data = (struct AUTH_DATA*) userdata;
	DBGINFO("%s Authenticating user ->%s<-\n", __func__, user);

	if (signature_state == SSH_PUBLICKEY_STATE_NONE){
		DBGINFO("Partial auth \n");
		return SSH_AUTH_SUCCESS;
	}

	if (signature_state != SSH_PUBLICKEY_STATE_VALID){
		DBGINFO("PUBLIC KEY INVALID\n");
		return SSH_AUTH_DENIED;
	}

	// valid so far.  Now look through keys for a match
	if (auth_data->ssh_data)
	{
		char ffn[1024]; //full filename and path
		ssh_key key;
		int result;
		struct stat buf;

		snprintf(ffn, 1024, "%s/authorized_keys",
		                      auth_data->ssh_data->auth_keys_folder);
		if (stat(ffn, &buf) == 0){
			result = ssh_pki_import_pubkey_file( ffn, &key );
			if ((result != SSH_OK) || (key==NULL))
				DBGINFO("unable to import public key file %s\n", ffn);
			else{
				result = ssh_key_cmp( key, pubkey, SSH_KEY_CMP_PUBLIC );
				ssh_key_free(key);
				if (result == 0) {
					auth_data->auth = 1;
					DBGINFO("key match\n");
					return SSH_AUTH_SUCCESS;
				}
			}
		}else
			DBGDEBUG("%s file missing\n", ffn);

	} else
		DBGERROR("missing ssh_data\n");

	// no matches
	auth_data->auth = 0;
	return SSH_AUTH_DENIED;
}

// This function is only to allow ssh app connections used for debugging
static int pty_request(ssh_session session, ssh_channel channel, const char *term, int x,int y, int px, int py, void *userdata){
	(void) session;
	(void) channel;
	(void) term;
	(void) x;
	(void) y;
	(void) px;
	(void) py;
	(void) userdata;
	DBGINFO("Allocated terminal\n");
	return 0;
}

// This function is only to allow ssh app connections used for debugging
static int shell_request(ssh_session session, ssh_channel channel, void *userdata){
	(void)session;
	(void)channel;
	(void)userdata;
	DBGINFO("Allocated shell\n");
	return 0;
}

struct ssh_channel_callbacks_struct channel_cb = {
    .channel_pty_request_function = pty_request,
    .channel_shell_request_function = shell_request
};

static ssh_channel new_session_channel(ssh_session session, void *userdata){
	(void) session;

	struct AUTH_DATA *auth_data = (struct AUTH_DATA*) userdata;
	if(*auth_data->chan != NULL){
		auth_data->auth_error =1;
		return NULL;
	}
	DBGINFO("Allocated session channel\n");
	*auth_data->chan = ssh_channel_new(session);
	// the following are only needed if we want the ssh app to connect for debug purposes.  dcal does not need pty nor shell.
	ssh_callbacks_init(&channel_cb);
	ssh_set_channel_callbacks(*auth_data->chan, &channel_cb);
	return *auth_data->chan;
}

// - server thread functions

// when a thread completes, it calls this routine so that it's thread id
// can be queued. At a later point, the list will be emptied and the
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

void * ssh_session_thread( void *param )
{
	process_buf_struct buf_struct = {0};
	ssh_channel chan=0;
	int nbytes, r;
	struct DISPATCH_DATA *dispatch_data = (struct DISPATCH_DATA*)param;
	struct AUTH_DATA *auth_data = dispatch_data->auth_data;
	struct SSH_DATA *ssh_data = dispatch_data->ssh_data;
	bool *alive, clear_lock = 1;
	ssh_session session;
	size_t nwritten, *const buf_size = &buf_struct.buf_size;
	char **const buf = &buf_struct.buf;
	ssh_event mainloop;
	int num_clients=0;

	auth_data->chan = &chan;
	auth_data->auth=0;
	auth_data->auth_error=0;
	auth_data->attempts=0;

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
	buf_struct.chan = chan;

	if (ssh_handle_key_exchange(session)) {
		DBGERROR("Error: ssh_handle_key_exchange: %s\n", ssh_get_error(session));
		goto exit_session;
	}

	if(*buf==NULL) {
		DBGERROR("Error: Unable to malloc buffer size:%d\n", INITIAL_BUFSIZE);
		goto exit_session;
	}

	if(ssh_data->method & METHOD_PASSWORD)
		ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
	else
		ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY);

	mainloop = ssh_event_new();
	if (mainloop==NULL){
		DBGERROR("ssh_event_new() failed.  Error: %s\n", ssh_get_error(session));
		goto exit_disconnect;
	}

	if (!(ssh_event_add_session(mainloop, session)==SSH_OK)){
		DBGERROR("ssh_event_add_session() failed.  Error: %s\n", ssh_get_error(session));
		goto exit_disconnect;
	}

	while(!(auth_data->auth && chan != NULL))
	{
		if (auth_data->auth_error)
			break;
		r = ssh_event_dopoll(mainloop, -1);
		if (r == SSH_ERROR){
			DBGERROR("ssh_event_dopoll() error: %s\n", ssh_get_error(session));
			break;
		}
	}

	if(!auth_data->auth) {
		DBGERROR("Authentication error: %s\n", ssh_get_error(session));
		goto exit_disconnect;
	}

//increment authorized client count
	sem_post(&dispatch_data->auth_clients_sem);

	DBGINFO("**** Successful connection\n");
	DBGDEBUG("AUTH_LOCK unlock line %d\n", __LINE__);
	//clear data from cb's user data:  (just paranoid - likely not necessary)
	memset(auth_data, 0, sizeof(*auth_data));
	clear_lock =0;
	pthread_mutex_unlock(&dispatch_data->auth_lock);

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

//only decrement the auth client count if leaving a thread that was authenticated
	sem_wait(&dispatch_data->auth_clients_sem);

	sem_getvalue(&dispatch_data->auth_clients_sem, &num_clients);

	if((ssh_data->ssh_disconnect) && (num_clients==0)){
		DBGINFO("Lost last ssh session - disabling radio\n");
		RadioDisable();
	}

exit_channel:
	if (chan)
		ssh_channel_close(chan);
	chan = NULL;
exit_disconnect:
	ssh_disconnect(session);
exit_session:
	ssh_free(session);
	session = NULL;
	if(buf_struct.buf)
		free(buf_struct.buf);
	if(clear_lock) {
		DBGDEBUG("AUTH_LOCK unlock line %d\n", __LINE__);
		pthread_mutex_unlock(&dispatch_data->auth_lock);
	}

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
	struct AUTH_DATA auth_data= {0};
	struct ssh_server_callbacks_struct cb = {
		.userdata = &auth_data,
		.auth_pubkey_function = auth_publickey,
		.channel_open_request_session_function = new_session_channel
	};
	dispatch_data.auth_data = &auth_data;

	if(ssh_data->method & METHOD_PASSWORD)
		cb.auth_password_function = auth_password;

	ssh_callbacks_init(&cb);

	sleep_duration.tv_sec =0;
	sleep_duration.tv_nsec = 10000000; // 10 ms

	i = 10;
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

	i=10;
	while( check_with_timeout (r=pthread_mutex_init(&dispatch_data.auth_lock,NULL),
	                           EAGAIN, &i, &sleep_duration));
	if (r)
	{
		DBGERROR("Mutex init failed with: %s\n", strerror(errno));
		return 1;
	}

	sem_init(&dispatch_data.auth_clients_sem, 0, 0);

	dispatch_data.alive = &ssh_data->alive;
	dispatch_data.exit_called = &ssh_data->reboot_on_exit;

	dispatch_data.thread_list = &ssh_data->thread_list;
	dispatch_data.completed.head = NULL;
	dispatch_data.ssh_data = ssh_data;

	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();

	*sshbind=ssh_bind_new();


	ssh_bind_options_set(*sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &(ssh_data->verbosity));
	ssh_bind_options_set(*sshbind, SSH_BIND_OPTIONS_BINDPORT, &(ssh_data->port));

	strncpy(key_tmp, ssh_data->host_keys_folder, MAX_PATH);
	strncat(key_tmp, "/ssh_host_dsa_key", MAX_PATH);
	DBGINFO("DSA host key: %s\n",key_tmp);
	ssh_bind_options_set(*sshbind, SSH_BIND_OPTIONS_DSAKEY, key_tmp );
	strncpy(key_tmp, ssh_data->host_keys_folder, MAX_PATH);
	strncat(key_tmp, "/ssh_host_rsa_key", MAX_PATH);
	DBGINFO("RSA host key: %s\n",key_tmp);
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

		pthread_mutex_lock(&dispatch_data.auth_lock);
		DBGDEBUG("AUTH_LOCK lock\n");
		auth_data.ssh_data = ssh_data;

		dispatch_data.session = ssh_new();
		r = ssh_bind_accept(*sshbind, dispatch_data.session);

		if(r==SSH_ERROR) {
			if (ssh_data->alive)
				DBGERROR("Error accepting a connection: %s\n", ssh_get_error(*sshbind));
			ssh_free(dispatch_data.session);
			dispatch_data.session = NULL;
			continue;
		}

		ssh_set_server_callbacks(dispatch_data.session, &cb);

		i = 10;
		while (check_with_timeout (r=pthread_create(&child, NULL,
		                                            &ssh_session_thread, &dispatch_data),
		                            EAGAIN, &i, &sleep_duration));
		if (r) {
			DBGERROR("Unable to start child thread: %s\n", strerror(r));
			ssh_data->alive = false; // kill any children
			ssh_free(dispatch_data.session);
			r=1;
			DBGDEBUG("AUTH_LOCK unlock at %d\n", __LINE__);
			pthread_mutex_unlock(&dispatch_data.auth_lock);
			break; // abort while loop
		}
		sem_wait(&dispatch_data.thread_init); // wait for child to copy data from stack
	}

	empty_completed_thread_list(&dispatch_data.completed);

cleanup:
	sem_destroy(&dispatch_data.auth_clients_sem);
	ssh_bind_free(*sshbind);
	ssh_finalize();
	pthread_mutex_destroy(&(dispatch_data.sdk_lock));
	pthread_mutex_destroy(&(dispatch_data.auth_lock));
	pthread_mutex_destroy(&dispatch_data.completed.lock);

	if (*dispatch_data.exit_called){
		// call system's reboot command rather then reboot API directly as the system version may do additional syncing.
		printf("***** calling reboot *****\n");
		system("reboot");
	}
	return r;
}
