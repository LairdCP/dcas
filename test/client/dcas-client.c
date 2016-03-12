#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "debug.h"

void ExitClean( int ExitVal );

static char * runtime_name = "";


int verify_knownhost(ssh_session session)
{
	REPORT_ENTRY_DEBUG;
	char *hexa;
	int state;
	char buf[10];
	unsigned char *hash = NULL;
	size_t hlen;
	ssh_key srv_pubkey;
	int rc;

	state=ssh_is_server_known(session);

	rc = ssh_get_publickey(session, &srv_pubkey);
	if (rc < 0) {
		return -1;
	}

	rc = ssh_get_publickey_hash(srv_pubkey,
	                            SSH_PUBLICKEY_HASH_SHA1,
	                            &hash,
	                            &hlen);
	ssh_key_free(srv_pubkey);
	if (rc < 0) {
		return -1;
	}

	switch(state) {
	case SSH_SERVER_KNOWN_OK:
		break; /* ok */
	case SSH_SERVER_KNOWN_CHANGED:
		fprintf(stderr,"Host key for server changed : server's one is now :\n");
		ssh_print_hexa("Public key hash",hash, hlen);
		ssh_clean_pubkey_hash(&hash);
		fprintf(stderr,"For security reason, connection will be stopped\n");
		return -1;
	case SSH_SERVER_FOUND_OTHER:
		fprintf(stderr,"The host key for this server was not found but an other type of key exists.\n");
		fprintf(stderr,"An attacker might change the default server key to confuse your client"
		        "into thinking the key does not exist\n"
		        "We advise you to rerun the client with -d or -r for more safety.\n");
		return -1;
	case SSH_SERVER_FILE_NOT_FOUND:
		fprintf(stderr,"Could not find known host file. If you accept the host key here,\n");
		fprintf(stderr,"the file will be automatically created.\n");
		/* fallback to SSH_SERVER_NOT_KNOWN behavior */
	case SSH_SERVER_NOT_KNOWN:
		hexa = ssh_get_hexa(hash, hlen);
		fprintf(stderr,"The server is unknown. Do you trust the host key ?\n");
		fprintf(stderr, "Public key hash: %s\n", hexa);
		ssh_string_free_char(hexa);
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			ssh_clean_pubkey_hash(&hash);
			return -1;
		}
		if(strncasecmp(buf,"yes",3)!=0) {
			ssh_clean_pubkey_hash(&hash);
			return -1;
		}
		fprintf(stderr,"This new key will be written on disk for further usage. do you agree ?\n");
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			ssh_clean_pubkey_hash(&hash);
			return -1;
		}
		if(strncasecmp(buf,"yes",3)==0) {
			if (ssh_write_knownhost(session) < 0) {
				ssh_clean_pubkey_hash(&hash);
				fprintf(stderr, "error %s\n", strerror(errno));
				return -1;
			}
		}

		break;
	case SSH_SERVER_ERROR:
		ssh_clean_pubkey_hash(&hash);
		fprintf(stderr,"%s",ssh_get_error(session));
		return -1;
	}
	ssh_clean_pubkey_hash(&hash);
	return 0;
}

int show_remote_processes(ssh_session session)
{
	ssh_channel channel;
	int rc;
	char buffer[256];
	int nbytes;

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return SSH_ERROR;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		return rc;
	}

	rc = ssh_channel_request_exec(channel, "ps aux");
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return rc;
	}

	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	while (nbytes > 0) {
		if (write(1, buffer, nbytes) != (unsigned int) nbytes) {
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			return SSH_ERROR;
		}
		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}

	if (nbytes < 0) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return SSH_ERROR;
	}

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return SSH_OK;
}

int main(int argc,char *argv[])
{
	REPORT_ENTRY_DEBUG;

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
			ExitClean(0);
		case 'h':
			ExitClean(0);
			break;
		}
	}

	ssh_session my_ssh_session;
	int verbosity = SSH_LOG_PROTOCOL;
	int rc;
	char *password = "summit";
	char *user = "root";

	my_ssh_session = ssh_new();
	if (my_ssh_session == NULL)
		ExitClean(-1);

	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "192.168.0.215");
	ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	if (ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user) < 0) {
		ssh_free(my_ssh_session);
		ExitClean(-1);
	}

	rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(my_ssh_session));
		ssh_free(my_ssh_session);
		ExitClean(-1);
	}

	// Verify the server's identity
	// For the source code of verify_knowhost(), check previous example
	if (verify_knownhost(my_ssh_session) < 0) {
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		ExitClean(-1);
	}

	// Authenticate ourselves
	rc = ssh_userauth_password(my_ssh_session, NULL, password);
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Error authenticating with password: %s\n",
		        ssh_get_error(my_ssh_session));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		ExitClean(-1);
	}

	printf("We're IN!\n");

	show_remote_processes(my_ssh_session);

	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
	ExitClean(0);
}

void ExitClean( int ExitVal )
{
	exit( ExitVal );
}
