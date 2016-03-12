#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "debug.h"

void ExitClean( int ExitVal );

static char * runtime_name = "";
ssh_session my_ssh_session = NULL;


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
		DBGERROR("Host key for server changed : server's one is now :\n");
		ssh_print_hexa("Public key hash",hash, hlen);
		ssh_clean_pubkey_hash(&hash);
		DBGERROR("For security reason, connection will be stopped\n");
		return -1;
	case SSH_SERVER_FOUND_OTHER:
		DBGERROR("The host key for this server was not found but an other type of key exists.\n");
		DBGERROR("An attacker might change the default server key to confuse your client"
		        "into thinking the key does not exist\n"
		        "We advise you to rerun the client with -d or -r for more safety.\n");
		return -1;
	case SSH_SERVER_FILE_NOT_FOUND:
		DBGERROR("Could not find known host file. If you accept the host key here,\n"
			"the file will be automatically created.\n");
		/* fallback to SSH_SERVER_NOT_KNOWN behavior */
	case SSH_SERVER_NOT_KNOWN:
		hexa = ssh_get_hexa(hash, hlen);
		DBGERROR("The server is unknown. Do you trust the host key ?\n"
			"Public key hash: %s\n", hexa);
		ssh_string_free_char(hexa);
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			ssh_clean_pubkey_hash(&hash);
			return -1;
		}
		if(strncasecmp(buf,"yes",3)!=0) {
			ssh_clean_pubkey_hash(&hash);
			return -1;
		}
		DBGERROR("This new key will be written on disk for further usage. do you agree ?\n");
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

#define LAIRD_HELLO "HELLO DCAS"
#define LAIRD_RESPONSE "WELCOME TO FAIRFIELD"

int remote_hello(ssh_session session)
{
	REPORT_ENTRY_DEBUG;

	ssh_channel channel;
	int rc;
	char buffer[256];
	int nbytes;
	int nwritten;

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return SSH_ERROR;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		return rc;
	}

	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return rc;
	}

	nbytes = 6;
	strncpy(buffer, "HELLO\n", nbytes);
	nwritten = ssh_channel_write(channel, LAIRD_HELLO, sizeof(LAIRD_HELLO));
	if (nwritten != sizeof(LAIRD_HELLO)) return SSH_ERROR;

	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

	if (nbytes < 0) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return SSH_ERROR;
	} else {
		DBGDEBUG("Response: %s\n", buffer);
		if(strncmp(buffer,LAIRD_RESPONSE,sizeof(LAIRD_RESPONSE))==0) {
			DBGINFO("Got proper response from the server\n");
			rc = SSH_OK;
		} else {
			rc = SSH_ERROR;
			DBGERROR("Got bad response from the server\n");
		}
	}

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return rc;
}

int main(int argc,char *argv[])
{
	REPORT_ENTRY_DEBUG;

	int verbosity = SSH_LOG_PROTOCOL;
	int rc;
	unsigned int port = 22;
	char *user = "root";
	char password[56];
	memset(password, 0, 56);
	strncpy(password, "summit", 56);
	bool usekey = false;

	// Define the options structure
	static struct option longopt[] = {
		{"host", required_argument, NULL, 'h'},
		{"port", required_argument, NULL, 'p'},
		{"user", required_argument, NULL, 'u'},
		{"pass", required_argument, NULL, 'P'},
		{"key", no_argument, NULL, 'k'},
		{"verbose", no_argument, NULL, 'v'},
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

	// Setup the ssh session first, our opts will adjust some options directly
	my_ssh_session = ssh_new();
	if (my_ssh_session == NULL)
		ExitClean(-1);

	// Set default
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
	if (ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user) < 0)
		ExitClean(-1);

	// Process command-line options
	runtime_name = argv[0]; // Save if needed later
	int c;
	int optidx=0;
	while ((c=getopt_long(argc,argv,"h:p:u:P:kv",longopt,&optidx)) != -1) {
		switch(c) {
		case 'v':
			ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
			break;
		case 'h':
			DBGDEBUG( "Setting host: %s\n", optarg );
			if (ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, optarg) < 0)
			{
				DBGERROR("Error setting host: %s\n", ssh_get_error(my_ssh_session));
				ExitClean(-1);
			}
			break;
		case 'p':
			port = atoi(optarg);
			DBGDEBUG( "Setting port: %u\n", port );
			if (ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port) < 0)
				ExitClean(-1);
			break;
		case 'u':
			DBGDEBUG( "Setting user: %s\n", optarg );
			if (ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, optarg) < 0)
				ExitClean(-1);
			break;
		case 'P':
			strncpy(password, optarg, 55);
			break;
		case 'k':
			DBGDEBUG( "Using auto-key authentication\n");
			usekey=true;
			break;
		}
	}

	rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK) {
		DBGERROR("Error connecting to localhost: %s\n", ssh_get_error(my_ssh_session));
		ExitClean(-1);
	}

	// Verify the server's identity
	// For the source code of verify_knowhost(), check previous example
	if (verify_knownhost(my_ssh_session) < 0) {
		DBGERROR("Unable to validate host\n");
		ExitClean(-1);
	}

	// Authenticate ourselves
	if (usekey)
		// Try automatic key-based auth, we don't support passphrases
		rc = ssh_userauth_publickey_auto(my_ssh_session, NULL, NULL);
	else
		// Default to trying password autentication
		rc = ssh_userauth_password(my_ssh_session, NULL, password);

	if (rc != SSH_AUTH_SUCCESS) {
		DBGERROR("Error authenticating: %s\n",
			ssh_get_error(my_ssh_session));
		ExitClean(-1);
	}

	DBGINFO("We're IN!\n");

	rc = remote_hello(my_ssh_session);

	if (rc == SSH_OK)
		ExitClean(0);
	else
		ExitClean(-1);
}

void ExitClean( int ExitVal )
{
	if(my_ssh_session != NULL) {
		if(ssh_is_connected(my_ssh_session))
			ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		my_ssh_session = NULL;
	}

	exit( ExitVal );
}
