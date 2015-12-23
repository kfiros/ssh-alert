/*******************************************************************
* Project:	SSH-Alert
*			SSH-Alert detects new SSH connection
*			attempts in real time and alerts the user.
*
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		main.c
* Description:	Main file of the project
*******************************************************************/

/*******************************************************************
* Includes
*******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include "includes/general.h"
#include "includes/ssh_alert.h"
#include "includes/logger.h"

/*******************************************************************
* Name:		print_usage
* Description:	Prints the correct usage message.
*******************************************************************/
void print_usage(void) {
	printf("ssh-alert [-p sshd_pid] [-l logfile]\n");
	printf("----------------------------------------------------\n");
	printf("ssh-alert 1.0 x86-64 Kfiros 2015\n");
	printf("ssh-alert detects new SSH connection attempts\n");
}

/*******************************************************************
* Name:		main
* Description:	Main function of the program.
*******************************************************************/
int main(int argc, char * argv[]) {
	int ret = SUCCESS;
	int call_rv;
	int option;
	pid_t arg_pid = -1;
	bool pflag = false, lflag = false;	
	char arg_log_path[MAX_PATH_LENGTH] = {0};
	
	UNUSED(pflag);

	DBG_PRINT("Installing Signal Handler");
	if (SIG_ERR == signal(SIGINT, SSH_ALERT_stop)) {
		fprintf(stderr, "[-] ERROR: Fatal error, Exiting \n");
		ret = ERR_MAIN_SIG_HANDLER_SETUP;
		goto cleanup;
	}

	/******************************
	* Parse command line
	* p - sshd pid (optional).
	* l - log file path (optional).
	******************************/
	DBG_PRINT("Parsing arguments");
	while (-1 != (option = getopt(argc, argv, "p:l:"))) {
		switch(option) {
			case 'p': 
				pflag = true;
				arg_pid = atoi(optarg);	
				if (0 >= arg_pid) {
					fprintf(stderr, "[-] ERROR: PID is invalid. Exiting \n");
					ret = ERR_MAIN_INVALID_PID_ARG;
					goto cleanup;
				}
				DBG_PRINT("Argument 'p' = %d ", arg_pid);
				break;

			case 'l': 
				lflag = true;
				strncpy(arg_log_path, optarg, MAX_PATH_LENGTH);
				DBG_PRINT("Argument 'l' = %s ", arg_log_path);
				break;

			default:
				print_usage();
				goto cleanup;
		}
	}	

	/* Init program logger */
	call_rv = LOGGER_init(lflag, arg_log_path);
	if (SUCCESS != call_rv) {
		fprintf(stderr, "[-] ERROR: logger initialization error. Exiting \n");
		ret = call_rv;
		goto cleanup;
	}

	LOGGER_log("[*] %s %s \n", APP_NAME, APP_VERSION);
	LOGGER_log("[*] Started logging to %s \n", LOGGER_get_log_path());

	/* Start the main logic of the ssh_alert module */
	call_rv = SSH_ALERT_start(arg_pid);
	if (SUCCESS != call_rv) {
		ret = call_rv;
		goto cleanup_logger;
	}

cleanup_logger:
	LOGGER_close();
cleanup:
	return ret;
}
