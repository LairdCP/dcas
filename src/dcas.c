#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

#include "debug.h"
#include "version.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

void PrintVersion( void );
void PrintHelp( void );
void ExitClean( int ExitVal );

static char * runtime_name = "";

#define SSHD_USER "libssh"
#define SSHD_PASSWORD "libssh"

#define LAIRD_HELLO "HELLO DCAS"
#define LAIRD_RESPONSE "WELCOME TO FAIRFIELD"

#define KEYS_FOLDER "./test/"
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
				printf("User %s wants to auth with pass %s\n",
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
				printf("User %s wants to auth with unknown auth %d\n",
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
int run_sshserver( void )
{
	ssh_session session;
	ssh_bind sshbind;
	ssh_message message;
	ssh_channel chan=0;
	char buf[2048];
	int auth=0;
	int shell=0;
	int i;
	int r;
	int verbosity = 0; // The enums described in the API document don't exist
	unsigned int port = 2222;

	sshbind=ssh_bind_new();
	session=ssh_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY,
	                     KEYS_FOLDER "ssh_host_dsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,
	                     KEYS_FOLDER "ssh_host_rsa_key");

	if(ssh_bind_listen(sshbind)<0) {
		printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
		return 1;
	}
	printf("Started sample libssh sshd on port %d\n", port);
	printf("You can login as the user %s with the password %s\n", SSHD_USER,
	       SSHD_PASSWORD);
	r = ssh_bind_accept(sshbind, session);
	if(r==SSH_ERROR) {
		printf("Error accepting a connection: %s\n", ssh_get_error(sshbind));
		return 1;
	}
	if (ssh_handle_key_exchange(session)) {
		printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
		return 1;
	}

	/* proceed to authentication */
	auth = authenticate(session);
	if(!auth) {
		printf("Authentication error: %s\n", ssh_get_error(session));
		ssh_disconnect(session);
		return 1;
	}

	DBGINFO("**** Successful connection\n");
	/* wait for a channel session */
	do {
		message = ssh_message_get(session);
		if(message) {
			if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
			    ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
				chan = ssh_message_channel_request_open_reply_accept(message);
				ssh_message_free(message);
				break;
			} else {
				ssh_message_reply_default(message);
				ssh_message_free(message);
			}
		} else {
			break;
		}
	} while(!chan);

	if(!chan) {
		printf("Error: cleint did not ask for a channel session (%s)\n",
		       ssh_get_error(session));
		ssh_finalize();
		return 1;
	}

	/* wait for a shell */
	do {
		message = ssh_message_get(session);
		if(message != NULL) {
			if(ssh_message_type(message) == SSH_REQUEST_CHANNEL &&
			    ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
				shell = 1;
				ssh_message_channel_request_reply_success(message);
				ssh_message_free(message);
				break;
			}
			ssh_message_reply_default(message);
			ssh_message_free(message);
		} else {
			break;
		}
	} while(!shell);

	if(!shell) {
		printf("Error: No shell requested (%s)\n", ssh_get_error(session));
		return 1;
	}

	printf("Client connected!\n");
	do {
		i=ssh_channel_read(chan,buf, 2048, 0);
		if(i>0) {
			if(*buf == '' || *buf == '')
				break;
			if(i == 1 && *buf == '\r')
				ssh_channel_write(chan, "\r\n", 2);
			else {
				buf[i] = '\0'; // be sure it's null terminated
				DBGINFO("Got from client: %s\n", buf);
				if (strncmp(buf, LAIRD_HELLO, sizeof(LAIRD_HELLO)) == 0) {
					DBGINFO("Got good protocol HELLO\n");
					ssh_channel_write(chan, LAIRD_RESPONSE, sizeof(LAIRD_RESPONSE));
					break;
				}
			}

		}
	} while (i>0);
	ssh_channel_close(chan);
	ssh_disconnect(session);
	ssh_bind_free(sshbind);

	ssh_finalize();

	return 0;
}

int main(int argc,char *argv[])
{
	REPORT_ENTRY_DEBUG;

	int rc = 0;

	// Define the options structure
	static struct option longopt[] = {
		{"daemon", no_argument, NULL, 'D'},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{NULL, 0, NULL, 0}
	};

#ifdef DEBUG_BUILD
	// Printout the command-line for debug purposes.
#define CMDLINE_BUFF_MAX 128
	char cmdline[CMDLINE_BUFF_MAX];
	snprintf( cmdline, CMDLINE_BUFF_MAX, "Program command: %s", argv[0]);
	for( int i = 1; i < argc; i++ ) {
		strncat( cmdline, " ", CMDLINE_BUFF_MAX-1-strlen(cmdline));
		strncat( cmdline, argv[i], CMDLINE_BUFF_MAX-1-strlen(cmdline));
	}
	DBGDEBUG("%s\n", cmdline);
#endif

	// Process command-line options
	runtime_name = argv[0]; // Save if needed later
	int c;
	int optidx=0;
	while ((c=getopt_long(argc,argv,"p:cvh",longopt,&optidx)) != -1) {
		switch(c) {
		case 'D':
			DBGDEBUG("Daemon mode enabled\n");
			break;

		case 'v':
			PrintVersion();
			ExitClean(0);
		case 'h':
			PrintVersion();
			PrintHelp();
			ExitClean(0);
			break;
		}
	}

	rc = run_sshserver();
	DBGDEBUG("Got %d return from run_sshserver()\n", rc);

	printf("Hello world\n");
	ExitClean(0);
}

void PrintVersion( void )
{
	// Display the copyright message
	printf("%s version: %s\n", runtime_name, _LRD_VERSION_STRING);
}

void PrintHelp( void )
{
}

void ExitClean( int ExitVal )
{
	exit( ExitVal );
}
