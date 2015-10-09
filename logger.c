/*******************************************************************
* Project:	SSH-Alert
*			SSH-Alert detects new SSH connection
*			attempts in real time and alerts the user.
*
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		logger.c
* Description:	Logging & user notifying
*******************************************************************/

/*******************************************************************
* Includes
*******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include "includes/general.h"
#include "includes/logger.h"
#include "includes/ssh_alert.h"

struct logger_info g_log_info;

/*******************************************************************
* Name: 	get_formatted_time
* Description:	Formats the input with a suitable time string.
*******************************************************************/
static void get_formatted_time(char * date_time, size_t max_length, time_t * time) {
	/* Get a formatted time string */
	strftime(date_time,
		max_length,
		TIME_FORMAT,
		localtime(time));
}

/*******************************************************************
* Name: 	format_conn_log_line
* Description:	Formats a log line according to the connection
*		details.
*******************************************************************/
static void format_conn_log_line(char * fmt, char * conn_log_line, struct ssh_conn_entry * conn) {
	struct in_addr ip_addr;
	char date_time[MAX_TIME_LENGTH];
	ip_addr.s_addr = conn->client_ip;

	/* Get a formatted time string */
	get_formatted_time(date_time, MAX_TIME_LENGTH, &(conn->conn_time));

	/* Create a format log line of the connection attempt */
	snprintf(conn_log_line,
		MAX_LOG_LINE,
		fmt,
		date_time, inet_ntoa(ip_addr));
}

/*******************************************************************
* Name: 	LOGGER_log_and_notify
* Description:	This function responsibles for logging and notifying
*		about new SSH connection attempt. 
*******************************************************************/
int LOGGER_log_and_notify(struct ssh_conn_entry * conn) {
	int ret = SUCCESS;
	int call_rv;
	char conn_log_line[MAX_LOG_LINE] = {0};
	char conn_notification_line[MAX_LOG_LINE] = {0};

	/* Log the connection attempt */
	format_conn_log_line(CONN_LOG_FMT, conn_log_line, conn);
	call_rv = LOGGER_log(conn_log_line);
	if (SUCCESS != call_rv) {
		ret = call_rv;
	}

	/* Notify the user */
	format_conn_log_line(CONN_NOTIFICATION_FMT, conn_notification_line, conn);
	call_rv = LOGGER_notify(conn_notification_line);
	if (SUCCESS != call_rv) {
		ret = call_rv;
	}

return ret;
}


/*******************************************************************
* Name:		LOGGER_notify
* Description:	Notify the user using `zenity`
*******************************************************************/
int LOGGER_notify(char * fmt, ...) {
	int ret = SUCCESS;
	int call_rv;
	va_list args;
	char fmt_message[MAX_LOG_LINE];
	char zenity_cmd[MAX_CMD_LINE];

	va_start(args, fmt);	
	vsnprintf(fmt_message, MAX_LOG_LINE, fmt, args);
	va_end(args);

	/* Format zenity cmd line */
	snprintf(zenity_cmd, MAX_CMD_LINE, ZENITY_CMD_FMT,
		ZENITY_MSG_TITLE, fmt_message);

	/* Notify the user */
	call_rv = system(zenity_cmd);
	if (-1 == call_rv) {
		ret = ERR_LOGGER_SYSTEM_ZENITY;
		goto cleanup;
	}

cleanup:
	return ret;
}

/*******************************************************************
* Name:		LOGGER_log
* Description:	Responsibles for logging messages to the program's
*		log file and screen.
*******************************************************************/
int LOGGER_log(char * fmt, ...) {
	int ret = SUCCESS;
	int call_rv;
	va_list args;

	/* Write to the screen */
	va_start(args, fmt);	
	vprintf(fmt, args);
	va_end(args);

	/* Write to log file */
	if (NULL == g_log_info.log_fd) {
		ret = ERR_LOGGER_INVALID_FD;
	}
	
	va_start(args, fmt);
	vfprintf(g_log_info.log_fd, fmt, args);	
	va_end(args);

	call_rv = fflush(g_log_info.log_fd);
	if (SUCCESS != call_rv) {
		ret = ERR_LOGGER_FLUSH;
	}

return ret;
}

/*******************************************************************
* Name:		LOGGER_close
* Description:	This function closes the resources which belong
*		to the logger module.
*******************************************************************/
void LOGGER_close(){
	/* Close the log file descriptor */
	if (NULL != g_log_info.log_fd) {
		fclose(g_log_info.log_fd);
	}
}

/*******************************************************************
* Name:		LOGGER_get_log_path
* Description:	Returns the log path, saved in the logger_info struct.
*******************************************************************/
char * LOGGER_get_log_path() {
	return g_log_info.log_path;
}

/*******************************************************************
* Name:		LOGGER_init
* Description:	Initializes the logger module. If needed it creates
*		the log file.
*******************************************************************/
int LOGGER_init(bool use_arg_log, char * arg_log_path) {
	int ret = SUCCESS;

	g_log_info.log_fd = NULL;	

	/* Copy the input log path into the global variable */	
	if (false == use_arg_log) {
		strncpy(g_log_info.log_path, DEFAULT_LOG_PATH, MAX_PATH_LENGTH);
	} else {
		strncpy(g_log_info.log_path, arg_log_path, MAX_PATH_LENGTH);
	}

	/* Open existing log file, or create one if doesn't exist */
	g_log_info.log_fd = fopen(g_log_info.log_path, "ab");	
	if (NULL == g_log_info.log_fd) {
		ret = ERR_LOGGER_OPENING_LOG_FILE;
		goto cleanup;	
	}

cleanup:
	return ret;
}

