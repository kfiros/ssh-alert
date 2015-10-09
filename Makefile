# SSH-Alert Makefile

# Compilation Parameters
CC=gcc
CFLAGS= -Iincludes -Wextra -Wall
SOURCES= main.c ssh_alert.c logger.c

all:
	$(CC) $(SOURCES) $(CFLAGS) -o ssh-alert
clean:
	rm -f ssh-alert
