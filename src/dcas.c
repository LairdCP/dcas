#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>

#include "debug.h"
#include "version.h"
#include "sdc_sdk.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include "../schema/dcal_builder.h"
#include "../schema/dcal_verifier.h"
#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(DCAL_session, x)
#include "support/hexdump.h"

void PrintVersion( void );
void PrintHelp( void );
void ExitClean( int ExitVal );

static char * runtime_name = "";

#define SSHD_USER "libssh"
#define SSHD_PASSWORD "libssh"

#define LAIRD_HELLO "HELLO DCAS"
#define LAIRD_RESPONSE "WELCOME TO FAIRFIELD"
#define LAIRD_BAD_BUFFER "BAD FLAT BUFFER"

#define DEFAULT_KEYS_FOLDER "/etc/dcas"
#define MAX_PATH 128
static char keys_folder[MAX_PATH];

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

int is_handshake_valid(void *buffer, size_t size)
{
	ns(Handshake_table_t) handshake;
	const char * ip;
	int ret;

	if((ret = ns(Handshake_verify_as_root(buffer, size, ns(Handshake_identifier))))){
		printf("could not verify buffer, got %s\n", flatcc_verify_error_string(ret));
		return 0;
	}

	if (!(handshake = ns(Handshake_as_root(buffer)))) {
		DBGERROR("Not a handshake\n");
		return 0;
	}

	if (ns(Handshake_server(handshake)) == true) {
		DBGERROR("Handshake marked as from server\n");
		return 0;
	}

	ip = ns(Handshake_ip(handshake));
	DBGINFO("Got ip: %s\n", ip);

	if (ns(Handshake_magic(handshake)) == ns(Magic_HELLO))
		return 1;

	return 0;
}

int build_handshake_ack(flatcc_builder_t *B, ns(Magic_enum_t) res_code)
{
	flatcc_builder_reset(B);
	ns(Handshake_start_as_root(B));
	ns(Handshake_server_add(B, true));
	ns(Handshake_magic_add(B, res_code));
	ns(Handshake_ip_create_str(B, "192.168.0.1"));
	ns(Handshake_end_as_root(B));
	return 0;
}

#define MAC_SZ 6
#define IP4_SZ 4
#define IP6_SZ 8

int build_status(flatcc_builder_t *B)
{
	CF10G_STATUS status;
	SDCERR result;
	LRD_WF_SSID ssid;
	memset(&status, 0, sizeof(CF10G_STATUS));
	result = GetCurrentStatus(&status);
	if (result!=SDCERR_SUCCESS)
		DBGERROR("GetCurrentStatus() failed with %d\n", result);
	result = LRD_WF_GetSSID(&ssid);
		DBGERROR("LRD_WF_GetSSID() failed with %d\n", result);

// only dealing with client mode for now
	flatcc_builder_reset(B);
	ns(Status_start_as_root(B));
	ns(Status_cardState_add(B, status.cardState));
	ns(Status_ProfileName_create_str(B, status.configName));
	ns(Status_ssid_create_str(B, (char *)ssid.val));
	ns(Status_channel_add(B, status.channel));
	ns(Status_rssi_add(B, status.rssi));
	ns(Status_clientName_create_str(B, status.clientName));
	ns(Status_mac_create(B, (char *)status.client_MAC, MAC_SZ));
	ns(Status_ip_create(B, (char *)status.client_IP, IP4_SZ));
	ns(Status_AP_mac_create(B, (char *)status.AP_MAC, MAC_SZ));
	ns(Status_AP_ip_create(B, (char *)status.AP_IP, IP4_SZ));
	ns(Status_AP_name_create_str(B, status.APName));
	ns(Status_bitRate_add(B, status.bitRate));
	ns(Status_txPower_add(B, status.txPower));
	ns(Status_dtim_add(B, status.DTIM));
	ns(Status_beaconPeriod_add(B, status.beaconPeriod));

	ns(Status_end_as_root(B));
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
	char key_tmp[MAX_PATH];

	sshbind=ssh_bind_new();
	session=ssh_new();

	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);

	strncpy(key_tmp, keys_folder, MAX_PATH);
	strncat(key_tmp, "/ssh_host_dsa_key", MAX_PATH);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, key_tmp );
	strncpy(key_tmp, keys_folder, MAX_PATH);
	strncat(key_tmp, "/ssh_host_rsa_key", MAX_PATH);
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, key_tmp);

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
		printf("Error: client did not ask for a channel session (%s)\n",
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

	flatcc_builder_t builder;
	flatcc_builder_init(&builder);
	void * handshake_buffer;
	size_t nbytes;
	size_t nwritten;

	do {
		i=ssh_channel_read(chan,buf, 2048, 0);
		if(i>0) {
			DBGINFO("Got %d bytes from client:\n", i);
			hexdump("Buffer", buf, i, stderr);

			flatcc_builder_t builder;
			flatcc_builder_init(&builder);

			if (is_handshake_valid(buf, i)) {
				DBGINFO("Got good protocol HELLO\n");
//TODO - deal with handshake for session management
//			build_handshake_ack(&builder, ns(Magic_ACK));
				build_status(&builder);
			}
			else
			{
				DBGINFO("failed to get HELLO\n");
				build_handshake_ack(&builder, ns(Magic_NACK));
			}
			handshake_buffer = flatcc_builder_get_direct_buffer(&builder, &nbytes);
			assert(handshake_buffer);
			DBGDEBUG("Created Handshake buffer size: %zd\n", nbytes);
			hexdump("Handshake buffer", handshake_buffer, nbytes, stderr);

			nwritten = ssh_channel_write(chan, handshake_buffer, nbytes);
			if (nwritten != nbytes) return SSH_ERROR;

		}
	} while (i>0);

	flatcc_builder_clear(&builder);
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
		{"keys", required_argument, NULL, 'k'},
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

	strncpy(keys_folder, DEFAULT_KEYS_FOLDER, MAX_PATH-1);

	// Process command-line options
	runtime_name = argv[0]; // Save if needed later
	int c;
	int optidx=0;
	while ((c=getopt_long(argc,argv,"Dk:hv",longopt,&optidx)) != -1) {
		switch(c) {
		case 'D':
			DBGDEBUG("Daemon mode enabled\n");
			break;
		case 'k':
			DBGDEBUG( "Setting key directory:%s\n", optarg );
			strncpy(keys_folder, optarg, MAX_PATH-1);
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

	do {
		rc = run_sshserver();
		DBGDEBUG("Got %d return from run_sshserver()\n", rc);
	} while(rc == 0);

	DBGDEBUG("DCAS Exiting\n");

	ExitClean(rc);
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
