/*****************************************************************************
Copyright 2012 Laboratory for Advanced Computing at the University of Chicago

This file is part of UDR.

Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions 
and limitations under the License.
*****************************************************************************/

#include <unistd.h>
#include <cstdlib>
#include <cstdio>

pid_t fork_execvp(const char *program, char* argv[], int * ptc, int * ctp){
  pid_t pid;

  int parent_to_child[2], child_to_parent[2];

  //need to figure out best way to do global parameters
  //char* arg;
  //int idx = 0;
  //while((arg = argv[idx]) != NULL){
  //  fprintf(stderr, "%s arg[%d]: %s\n", program, idx, arg);
  //  idx++;
  //}

  if(pipe(parent_to_child) != 0 || pipe(child_to_parent) != 0){
    perror("Pipe cannot be created");
    exit(1);
  }

  pid = fork();

  if(pid == 0){
    //child
    close(parent_to_child[1]);
    dup2(parent_to_child[0], 0);
    close(child_to_parent[0]);
    dup2(child_to_parent[1], 1);

    execvp(program, argv);
    perror(program);
    exit(1);
  }
  else if(pid == -1){
    fprintf(stderr, "Error starting %s\n", program);
    exit(1);
  }
  else{
    //parent
    close(parent_to_child[0]);
    *ptc = parent_to_child[1];
    close(child_to_parent[1]);
    *ctp = child_to_parent[0];
  }
  return pid;
}
