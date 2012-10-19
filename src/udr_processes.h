#ifndef UDR_PROCESSES_H
#define UDR_PROCESSES_H

pid_t fork_execvp(const char *program, char* argv[], int * ptc, int * ctp);

#endif