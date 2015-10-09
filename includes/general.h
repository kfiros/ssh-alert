/*******************************************************************
* Project:	SSH-Alert
*			SSH-Alert detects new SSH connection
*			attempts in real time and alerts the user.
*
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		general.h
* Description:	Project's general header file
*******************************************************************/

#ifndef __GENERAL_H__
#define __GENERAL_H__

/*******************************************************************
* Constants
*******************************************************************/

/* Application parameters */
#define DEBUG (1)
#define APP_VERSION ("v1.0")
#define APP_NAME ("SSH-Alert")

/* Application return values */
enum errors {
	SUCCESS = 0,

	ERR_MAIN = 1000,
	ERR_MAIN_SIG_HANDLER_SETUP,
	ERR_MAIN_INVALID_ARGS_COUNT,
	ERR_MAIN_INVALID_PID_ARG,

	ERR_SSH = 2000,
	ERR_SSH_PTRACE_ATTACH,
	ERR_SSH_PTRACE_ATTACH_WAIT,
	ERR_SSH_PTRACE_SYSCALL,
	ERR_SSH_PTRACE_SYSCALL_WAIT,
	ERR_SSH_PTRACE_SYSCALL_GETREGS,
	ERR_SSH_PTRACE_TRACEE_EXITED,
	ERR_SSH_REMOTE_ADDR_NULL_POINTER,
	ERR_SSH_CALLOC_USER_MEM,
	ERR_SSH_PTRACE_PEEK_TRACEE_DATA,
	ERR_SSH_OPEN_PID_FILE,
	ERR_SSH_READ_PID_FILE,
	ERR_SSH_PID_CONVERTION,
	ERR_SSH_STOP_SSHD_PROCESS_SIG,
	ERR_SSH_WAIT_SSHD_STOP_SIG,
	ERR_SSH_DETACH_WAIT,
	ERR_SSH_PTRACE_DETACH,
	ERR_SSH_DETACH_CONTINUE,

	ERR_LOGGER = 3000,
	ERR_LOGGER_OPENING_LOG_FILE,
	ERR_LOGGER_INVALID_FD,
	ERR_LOGGER_LOG_MESSAGE,
	ERR_LOGGER_FLUSH,
	ERR_LOGGER_SYSTEM_ZENITY,
};


typedef enum {
	false = 0,
	true
} bool;

#define MAX_PATH_LENGTH (255)


/*******************************************************************
* Macros
*******************************************************************/
#if DEBUG
	#define DBG_PRINT(fmt, args...) do { fprintf(stderr, "[*] DEBUG: " fmt "\n" \
						, ##args); } while (false)
#else
	#define DBG_PRINT(...) do {} while (false)
#endif

#define UNUSED(expr) do { (void)(expr); } while (false)

#endif /* __GENERAL_H__ */



