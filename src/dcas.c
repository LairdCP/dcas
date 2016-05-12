#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h> //only needed for sleep prior to exit

#include "debug.h"
#include "version.h"
#include "ssh_server.h"

void PrintVersion( void );
void PrintHelp( void );
void ExitClean( int ExitVal );

static char * runtime_name = "";
#define DEFAULT_KEYS_FOLDER "/etc/dcas"

static struct SSH_DATA ssh_data = {
	.alive = true,
	.port = 2222,
	.verbosity = 0,
};

void sigproc(int unused)
{
	DBGINFO("signal caught. Marking loop and threads for exit\n");
	ssh_data.alive = false;
	sem_post(&ssh_data.thread_list);
}

int main(int argc,char *argv[])
{
	REPORT_ENTRY_DEBUG;

	int rc = 0;

	signal(SIGINT, sigproc);
	signal(SIGQUIT, sigproc);
	signal(SIGTERM, sigproc);

	// Define the options structure
	static struct option longopt[] = {
		{"daemon", no_argument, NULL, 'D'},
		{"keys", required_argument, NULL, 'k'},
		{"help", no_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'v'},
		{"port", required_argument, NULL, 'p'},
		//TODO: add a verbose or logging flag
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

	strncpy(ssh_data.keys_folder, DEFAULT_KEYS_FOLDER, MAX_PATH-1);

	// Process command-line options
	runtime_name = argv[0]; // Save if needed later
	int c;
	int optidx=0;
	while ((c=getopt_long(argc,argv,"Dk:hvp:",longopt,&optidx)) != -1) {
		switch(c) {
		case 'D':
			DBGDEBUG("Daemon mode enabled\n");
			break;
		case 'k':
			DBGDEBUG( "Setting key directory:%s\n", optarg );
			strncpy(ssh_data.keys_folder, optarg, MAX_PATH-1);
			break;
		case 'v':
			PrintVersion();
			ExitClean(0);
		case 'h':
			PrintVersion();
			PrintHelp();
			ExitClean(0);
			break;
		case 'p':
			ssh_data.port = atoi(optarg);
			DBGDEBUG("Setting port to %d\n", ssh_data.port);
			break;
		}
	}

	sem_init(&ssh_data.thread_list, 0, MAX_THREADS);

	rc = run_sshserver( &ssh_data );
	DBGDEBUG("Got %d return from run_sshserver()\nDCAS Exiting\n", rc);

	sem_destroy(&ssh_data.thread_list);
	ExitClean( rc );
}

void PrintVersion( void )
{
	// Display the copyright message
	printf("%s version: %s\n", runtime_name, _LRD_VERSION_STRING);
}

void PrintHelp( void )
{
	printf("\nDevice Control API Service\n\n"
	       "\tThis application is used to provide services for a\n"
	       "\tDevice Control API Layer (dcal) application on a remote\n"
	       "\thost to be able to configure the WB system.\n\n"
	       "\tUsage:\n"
	       "\t%s [-Dkvhp]\n\n"
	       "\t\t-D\t\tDaemon mode\n"
	       "\t\t-k <path>\tkey directory path\n"
	       "\t\t-v\t\tversion\n"
	       "\t\t-h\t\thelp\n"
	       "\t\t-p <port>\ttcp port to listen for connections\n"
	       "\n\n", runtime_name);
}

void ExitClean( int ExitVal )
{
	exit( ExitVal );
}
