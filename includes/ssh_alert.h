/*******************************************************************
* Project:	SSH-Alert
*			SSH-Alert detects new SSH connection
*			attempts in real time and alerts the user.
*
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		ssh_alert.h
* Description:	Header file for ssh_alert.c
*******************************************************************/

#ifndef __SSH_ALERT_H__
#define __SSH_ALERT_H__

/*******************************************************************
* Includes
*******************************************************************/
#include <arpa/inet.h>

/*******************************************************************
* Constants & Macros
*******************************************************************/
#define SSHD_PID_FILE ("/var/run/sshd.pid")
#define SSHD_PID_FILE_MAX_SIZE (6)


/*******************************************************************
* Structs
*******************************************************************/
struct ssh_conn_entry {
	uint32_t client_ip;	
	time_t conn_time;
};

/*******************************************************************
* Prototypes 
*******************************************************************/
int	SSH_ALERT_start(pid_t arg_pid);
void	SSH_ALERT_stop();

#endif /* __SSH_ALERT_H__ */
