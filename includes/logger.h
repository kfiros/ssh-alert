/*******************************************************************
* Project:	SSH-Alert
*			SSH-Alert detects new SSH connection
*			attempts in real time and alerts the user.
*
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		logger.h
* Description:	Logger header file
*******************************************************************/

#ifndef __LOGGER_H__
#define __LOGGER_H__

/*******************************************************************
* Includes
*******************************************************************/
#include "ssh_alert.h"

/*******************************************************************
* Constants
*******************************************************************/
#define MAX_LOG_LINE (512)
#define MAX_CMD_LINE (512)
#define DEFAULT_LOG_PATH ("/var/log/ssh-alert.log\0")

#define ZENITY_MSG_TITLE ("New SSH Connection")
#define ZENITY_CMD_FMT ("zenity --warning --title='%s' --text='%s' \
--no-wrap > /dev/null 2>&1 &")

#define TIME_FORMAT ("%b %d %H:%M:%S")
#define MAX_TIME_LENGTH (128)





#define CONN_NOTIFICATION_FMT ("SSH-Alert identified a new connection attempt to your system.\
\n\tTime:\t%s \n\tIP:\t\t%s\n")

#define CONN_LOG_FMT ("%s Connection attempt from %s\n")

/*******************************************************************
* Structs
*******************************************************************/
struct logger_info {
	char log_path[MAX_PATH_LENGTH];
	FILE * log_fd;
};

/*******************************************************************
* Prototypes 
*******************************************************************/
int	LOGGER_log(char * fmt, ...);
int	LOGGER_notify(char * fmt, ...);
int	LOGGER_log_and_notify(struct ssh_conn_entry * conn);
int	LOGGER_init(bool use_default, char * arg_log_path);
void	LOGGER_close();
char *	LOGGER_get_log_path();

#endif /* __LOGGER_H__ */
