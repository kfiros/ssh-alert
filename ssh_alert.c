/*******************************************************************
* Project:	SSH-Alert
*			SSH-Alert detects new SSH connection
*			attempts in real time and alerts the user.
*
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		ssh_alert.c
* Description:	This file contains the main logic for SSH connections
*		monitoring.
*******************************************************************/

/*******************************************************************
* Includes
*******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "includes/general.h"
#include "includes/ssh_alert.h"
#include "includes/logger.h"

pid_t g_sshd_pid = -1;

/*******************************************************************
* Name: 	get_sockaddr_rounded_size
* Description:	This function calculates the size of the sockaddr
*		struct in bytes, rounded upward (by int size).
*******************************************************************/
static int get_sockaddr_rounded_size() {
	return sizeof(struct sockaddr) + \
			(sizeof(int) - sizeof(struct sockaddr) % (sizeof(int)));
}

/*******************************************************************
* Name: 	read_proc_mem
* Description:	This function reads remote process' memory, using
		PTRACE_PEEKDATA. The read block size is sizeof(int).
*******************************************************************/
static int read_proc_mem(pid_t sshd_pid,
			int * remote_addr,
			int * read_mem,
			size_t num_memb) {
	int ret = SUCCESS;
	unsigned int i = 0;

	if (NULL == remote_addr) {
		ret = ERR_SSH_REMOTE_ADDR_NULL_POINTER;
		goto cleanup;
	}

	errno = 0;
	/* Read sshd process' sockkadr struct from its memory */
	for(i = 0; num_memb > i; ++i) {
		read_mem[i] = ptrace(PTRACE_PEEKDATA,
					sshd_pid, (int *) remote_addr + i,
					NULL);
		if (0 != errno) {
			ret = ERR_SSH_PTRACE_PEEK_TRACEE_DATA;
			goto cleanup;
		}
	}

cleanup:
	return ret;
}

/*******************************************************************
* Name: 	hook_accept
* Description:	This function examines the 'accept' syscall. Before
*		the 'accept' syscall returns, it acquires its 
*		arguments.
*******************************************************************/
static int hook_accept(pid_t sshd_pid, struct user_regs_struct * uregs) {
	int ret = SUCCESS;
	int call_rv;
	struct ssh_conn_entry conn = {0};
	size_t read_mem_size;
	int * read_mem = NULL;

	/* Calculate the size of memory needed to be read from the sshd process */
	read_mem_size = get_sockaddr_rounded_size();
	read_mem = calloc(1, read_mem_size);
	if (NULL == read_mem) {
		ret = ERR_SSH_CALLOC_USER_MEM;
		goto cleanup;
	}	

	/* Syscall parameters convention (x86-64) - %rdi, %rsi, %rdx, %r10, %r8, %r9 */
	/* accept(int sockfd, struct sockaddr * addr, socklen_t * addrlen) */
	call_rv = read_proc_mem(sshd_pid,
				(int * ) uregs->rsi,
				read_mem,
				read_mem_size / sizeof(int));
	if (SUCCESS != call_rv) {	
		ret = call_rv;
		goto cleanup;
	}

	/* Assign the required data in the ssh_conn_entry struct */
	conn.client_ip = ((struct sockaddr_in *) read_mem)->sin_addr.s_addr;
	conn.conn_time = time(NULL);
	
	/* Log and notify about new ssh connection attempt */
	LOGGER_log_and_notify(&conn);

cleanup:
	if (NULL != read_mem) {
		free(read_mem);
	}

	return ret;	
}

/*******************************************************************
* Name: 	hook_connections
* Description:	This function polls on syscalls and wait for the
*		'accept' syscall. When 'accept' syscall is revealed,
*		it handles it accordingly.
*******************************************************************/
static int hook_connections(pid_t sshd_pid) {
	int ret = SUCCESS;
	int call_rv;
	int status;
	int sig = 0;
	struct user_regs_struct uregs;
	bool enter = true; 

	while (true) {
		/* Intercept the next syscall */	
		call_rv = ptrace(PTRACE_SYSCALL, sshd_pid, 0, sig);
		if (-1 == call_rv) {
			ret = ERR_SSH_PTRACE_SYSCALL;
			goto cleanup;	
		}

		/* Wait for signals */
		call_rv = waitpid(-1, &status, __WALL);
		if (-1 == call_rv) {
			ret = ERR_SSH_PTRACE_SYSCALL_WAIT;
			goto cleanup;
		}

		/* In case child exited */
		if (WIFEXITED(status)) {
			ret = ERR_SSH_PTRACE_TRACEE_EXITED;
			goto cleanup;
		}

		if (WIFSTOPPED(status)){
			sig = WSTOPSIG(status);
			/* Check for other signals except SIGTRAP */
			if (SIGTRAP != sig) { 
				/* In this case - we need to signal the child process
				and restart the syscall... */
				continue;
			} else {
				sig = 0;
			}
		}
		
		/* Get user registers */
		call_rv = ptrace(PTRACE_GETREGS, sshd_pid, 0, &uregs);	
		if (-1 == call_rv) {
			ret = ERR_SSH_PTRACE_SYSCALL_GETREGS;
			goto cleanup;
		}

		/* Checking for an accept syscall */
		if(SYS_accept == uregs.orig_rax) {
			/* Intercept the function only when it returns */
			if (true == enter) {
				enter = false;

			} else {
				enter = true;
				call_rv = hook_accept(sshd_pid, &uregs);
				if (SUCCESS != call_rv) {
					ret = call_rv;
					goto cleanup;
				}
			}
		}
	}

cleanup:
	return ret;
}


/*******************************************************************
* Name: 	obtain_sshd_pid
* Description:	This function obtains the sshd PID from its pid file,
*		usually located at /var/run/sshd.pid. Obviously there
*		are other ways to accomplish this task, however, I find
*		my way very hermetic.
*******************************************************************/
static int obtain_sshd_pid(pid_t * sshd_pid) {
	int ret = SUCCESS;
	long int converted_pid;
	FILE * sshd_pid_fd = NULL;
	char read_buff[SSHD_PID_FILE_MAX_SIZE];
	char * endptr;

	/* Open the sshd.pid file for reading */
	sshd_pid_fd = fopen(SSHD_PID_FILE, "rb");
	if (NULL == sshd_pid_fd) {
		LOGGER_log("ERROR: Cannot open %s file \n", SSHD_PID_FILE);
		ret = ERR_SSH_OPEN_PID_FILE;
		goto cleanup;
	}
	
	/* Read from the requested file */
	if (NULL == fgets(read_buff,
			SSHD_PID_FILE_MAX_SIZE,
			sshd_pid_fd)) {
		LOGGER_log("ERROR: Cannot read from sshd.pid file \n");
		ret = ERR_SSH_READ_PID_FILE;
		goto cleanup;
	}

	/* Set errno to zero before converting the pid string */ 
	errno = 0;

	converted_pid = strtol(read_buff, &endptr, 10);
	if ((ERANGE == errno && (LONG_MAX == converted_pid || LONG_MIN == converted_pid)) ||
		(0 != errno && 0 == converted_pid) || (read_buff == endptr)) {
		ret = ERR_SSH_PID_CONVERTION;
		goto cleanup;
	}

	*sshd_pid = (pid_t) converted_pid;

cleanup:
	if (NULL != sshd_pid_fd) {
		fclose(sshd_pid_fd);
	}
	return ret;
}

/*******************************************************************
* Name: 	attach_remote_process
* Description:	This function attaches to the remote sshd process.
*		Actually, in this version of the program, there is
*		no distinction between real sshd processes and other
*		processes.
*******************************************************************/
static int attach_remote_process(pid_t sshd_pid) {
	int ret = SUCCESS;
	int call_rv;
	int status;

	LOGGER_log("[*] Attaching to process: %d\n", sshd_pid);
	call_rv = ptrace(PTRACE_ATTACH, sshd_pid, 0, 0);
	if (-1 == call_rv) {
		ret = ERR_SSH_PTRACE_ATTACH;
		goto cleanup;
	}

	/* Wait for signal status from the attached process */
	call_rv = waitpid(-1, &status, __WALL);
	if (-1 == call_rv) {
		ret = ERR_SSH_PTRACE_ATTACH_WAIT;
		goto cleanup;
	}

cleanup:
	return ret;
}

/*******************************************************************
* Name: 	SSH_ALERT_start
* Description:	Main entry point of the ssh_alert module. This function
*		attaches to the sshd process and starts monitoring it.
*******************************************************************/
int SSH_ALERT_start(pid_t arg_pid) {
	int ret = SUCCESS;
	int call_rv;
	pid_t sshd_pid;

	/* Obtain the pid of the running sshd deamon */
	if (-1 != arg_pid) { /* As argument */
		sshd_pid = arg_pid;
	} else {
		call_rv = obtain_sshd_pid(&sshd_pid); /* From pid file */
		if (SUCCESS != call_rv) {
			ret = call_rv;	
			goto cleanup;
		}
	}
	
	g_sshd_pid = sshd_pid;

	/* Attach to the remote process */
	call_rv = attach_remote_process(sshd_pid);
	if (SUCCESS != call_rv) {
		LOGGER_log("ERROR: Couldn't attach to remote process \n");
		ret = call_rv;
		goto cleanup;
	}

	LOGGER_log("[*] Attached to process successfully \n");	

	/* Poll on syscalls and hook the `accept` syscall */
	call_rv = hook_connections(sshd_pid);
	if (SUCCESS != call_rv) {
		LOGGER_log("ERROR: Critical error while tracing the SSH process \n");
		ret = call_rv;
		goto cleanup;
	}

cleanup:
	return ret;
}

/*******************************************************************
* Name: 	SSH_ALERT_stop
* Description:	When SIGINT is raised, this function is called. 
*		It detaches from the SSHD process, in order to
*		restore it to its original state.
*******************************************************************/
void SSH_ALERT_stop() {
	int ret = SUCCESS;
	int call_rv;
	int status;

	/* Check whether we already attached to the SSHD process */
	if (-1 == g_sshd_pid) {
		/* If not, exit */
		goto cleanup;
	}

	LOGGER_log("\n[*] Detaching from remote sshd process \n");

	/* First - we need to stop the remote SSHD process. Only afterward
	* we are able to detach from the sshd process. */
	call_rv = kill(g_sshd_pid, SIGSTOP);
	if (SUCCESS != call_rv) {
		ret = ERR_SSH_STOP_SSHD_PROCESS_SIG;
		goto cleanup;
	}

	call_rv = waitpid(g_sshd_pid, &status, 0);
	if (-1 == call_rv) {
		ret = ERR_SSH_DETACH_WAIT;
		goto cleanup;
	}
	
	if (!(WIFSTOPPED(status))) {	
		ret = ERR_SSH_WAIT_SSHD_STOP_SIG;
		goto cleanup;
	}

	/* Detach */
	call_rv = ptrace(PTRACE_DETACH, g_sshd_pid, 0, 0);
	if (-1 == call_rv) {
		ret = ERR_SSH_PTRACE_DETACH;
		goto cleanup;
	}
	
	/* Finally, we continue the SSHD process with a SIGCONT signal */
	call_rv = kill(g_sshd_pid, SIGCONT);
	if (SUCCESS != call_rv) {
		ret = ERR_SSH_DETACH_CONTINUE;
		goto cleanup;
	}

cleanup:
	if (SUCCESS != ret) {
		LOGGER_log("ERROR: Failed detaching from remote SSHD process.\n\
The SSHD daemon may left in an unstable state. \n");
	} else {
		LOGGER_log("[*] Detached successfully \n");
	}

	/* In any case, exit */
	LOGGER_log("[*] Exiting \n");
	exit(ret);
}
