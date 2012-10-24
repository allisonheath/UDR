#ifndef UDR_SERVER_H
#define UDR_SERVER_H

pid_t fork_execvp(const char *program, char* argv[], int * ptc, int * ctp);
int run_as_server(char * dir, char * port, char * udr_program_dest);
int get_server_connection(char * host, char * port, char * udr_cmd, char * line, int line_size);

#endif