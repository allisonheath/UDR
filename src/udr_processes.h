#ifndef UDR_PROCESSES_H
#define UDR_PROCESSES_H

pid_t fork_execvp(const char *program, char* argv[], int * ptc, int * ctp);
int run_as_daemon(char * dir, char * port, char * udr_program_dest);
int get_daemon_connection(char * host, char * port, char * udr_cmd, char * line, int line_size);

#endif