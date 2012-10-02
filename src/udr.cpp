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
#include <cstring>
#include <netdb.h>
#include <iostream>
#include <sstream>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <udt.h>
#include "udr.h"
#include "crypto.h"
#include "cc.h"
#include "udr_threads.h"

using namespace std;

bool verbose_mode = false;
bool encryption = true;

const char *ssh_program = "ssh";
const char *rsync_program = "rsync";
char *key_base_filename = ".udr_key";
const char * which_process;

char udr_program_src[PATH_MAX];
char * udr_program_dest = NULL;

pid_t ssh_pid = -1;
pid_t rsync_pid = -1;

int default_start_port = 9000;
int default_end_port = 9100;

int run_ssh(const char* host, const char* remuser, const char *cmd, int *ptc, int *ctp){

    if (verbose_mode)
      fprintf(stderr,
       "%s Executing: program %s host %s, user %s, command %s\n", which_process,
       ssh_program, host,
       remuser ? remuser : "(unspecified)", cmd);

    int parent_to_child[2];
    int child_to_parent[2];

    if (pipe(child_to_parent) < 0){
      perror("Pipe to ssh not created");
      return -1;
    }
    if (pipe(parent_to_child) < 0){
      perror("Pipe from ssh not created");
      return -1;
    }

    ssh_pid = fork();
    if (ssh_pid == 0){
      close(child_to_parent[0]);
      dup2(child_to_parent[1], 1); 
      close(child_to_parent[1]);

      close(parent_to_child[1]);
      dup2(parent_to_child[0], 0);
      close(parent_to_child[0]);

      if (remuser) {
        execlp(ssh_program, ssh_program, "-l", remuser, host, cmd, NULL);
      }
      else{
        execlp(ssh_program, ssh_program, host, cmd, NULL);
      }
      
      perror(ssh_program);
      exit(1);
    }
    else if (ssh_pid == -1){
      cerr << "ERROR STARTING SSH" << endl;
      exit(1);
    }
    else{
      if(verbose_mode)
        fprintf(stderr, "%s The ssh_pid is %i\n", which_process, ssh_pid);

      close(child_to_parent[1]);
      *ctp = child_to_parent[0];

      close(parent_to_child[0]);
      *ptc = parent_to_child[1];
    }
    return 0;
}

int run_rsync(char* rsync_argv[], int * ptc, int * ctp){
  char* arg;
  int idx = 0;
  while((arg = rsync_argv[idx]) != NULL){
    if(verbose_mode){
      fprintf(stderr, "%s rsync arg[%d]: %s\n", which_process, idx, arg);
    }
    idx++;
  }

  int parent_to_child[2], child_to_parent[2];

  if(pipe(parent_to_child) != 0 || pipe(child_to_parent) != 0){
    perror("Pipe to rsync cannot be created");
    exit(1);
  }

  rsync_pid = fork();

  if(rsync_pid == 0){
    //child
    close(parent_to_child[1]);
    dup2(parent_to_child[0], 0);
    close(child_to_parent[0]);
    dup2(child_to_parent[1], 1);

    execvp(rsync_program, rsync_argv);
    perror(rsync_program);
    exit(1);
  }
  else if(rsync_pid == -1){
    cerr << "Error starting rsync" << endl;
    exit(1);
  }
  else{
    //parent
    close(parent_to_child[0]);
    *ptc = parent_to_child[1];
    close(child_to_parent[1]);
    *ctp = child_to_parent[0];
  }

  return rsync_pid;
}

void usage(){
  fprintf(stderr, "usage: udr [-n] [-c remote udr location] rsync [rsync options]\n");
  exit(1);
}

//only going to go from local -> remote and remote -> local, remote <-> remote maybe later, but local -> local doesn't make sense for UDR
int main(int argc, char* argv[]){
  int ch, tflag, sflag, rflag, use_rsync, rsync_arg_idx;
  char * port_num = NULL;
  char * host = NULL;
  char * key_dir = NULL;
  char * key_filename = NULL;
  char * username = NULL;
  bool local_to_remote, remote_to_local;
  local_to_remote = remote_to_local = false;

  tflag = sflag = use_rsync = rsync_arg_idx = 0;

  if(argc < 1)
    usage();

  char *ptr = realpath(argv[0], udr_program_src);

  for(int i = 0; i < argc; i++){
    if(strcmp(argv[i], "rsync") == 0){
      use_rsync = 1;
      rsync_arg_idx = i;
      break;
    }
  }

  if(!use_rsync)
    usage();
  
  while((ch = getopt(rsync_arg_idx, argv, "tlnvs:h:p:c:k:")) != -1)
    switch (ch) {
      case 't':
      tflag = 1;
      break;
      case 'n':
      encryption = false;
      break;
      case 's':
      sflag = 1;
      port_num = optarg;
      break;
      case 'l':
      username = optarg;
      break;
      case 'p':
      key_filename = optarg;
      break;
      case 'c':
      udr_program_dest = optarg;
      break;
      case 'k':
      key_dir = optarg;
      break;
      case 'v':
      verbose_mode = true;
      break;
      default:
      cerr << "Illegal argument: " << (char)ch << endl;
      usage();
    }

    if(udr_program_dest == NULL){
      udr_program_dest = "udr";
    }

    if(verbose_mode){
      if(sflag)
        which_process = "Sender:";
      else if(tflag)
        which_process = "Receiver:";
      else
        which_process = "Original:";

      fprintf(stderr, "%s Local program: %s Remote program: %s Encryption: %d\n", which_process, udr_program_src, udr_program_dest, encryption);
    }

    if(tflag){
      run_receiver(default_start_port, default_end_port, encryption, verbose_mode);
      if(verbose_mode)
        fprintf(stderr, "%s run_receiver done\n", which_process);
    }
    else if(sflag){
      string arguments = "";
      string sep = "";
      char** rsync_args = &argv[rsync_arg_idx];
      int rsync_argc = argc - rsync_arg_idx;
      char hex_pp[HEX_PASSPHRASE_SIZE];
      unsigned char passphrase[PASSPHRASE_SIZE];

      if(encryption){
        if(verbose_mode)
          fprintf(stderr, "%s Key filename: %s\n", which_process, key_filename);
        FILE* key_file = fopen(key_filename, "r");
        if(key_file == NULL){
          fprintf(stderr, "ERROR: could not read from key_file %s\n", key_filename);
          exit(-1);
        }
        fscanf(key_file, "%s", hex_pp);
        fclose(key_file);
        remove(key_filename);

        for(int i = 0; i < strlen(hex_pp); i=i+2){
          unsigned int c;
          sscanf(&hex_pp[i], "%02x", &c);
          passphrase[i/2] = (unsigned char)c;
        }

      }

      host = argv[rsync_arg_idx-1];

      if(verbose_mode)
        fprintf(stderr, "%s Host: %s\n", which_process, host);

      for(int i = 0; i < rsync_argc; i++){ 
        if(verbose_mode)
          fprintf(stderr, "%s rsync arg[%d]: %s\n", which_process, i, rsync_args[i]);

        arguments += sep;
        sep = " ";
        arguments += rsync_args[i];
      }

      run_sender(host, port_num, encryption, passphrase, verbose_mode, arguments.c_str(), rsync_argc, rsync_args);
      if(verbose_mode)
        fprintf(stderr, "%s run_sender done\n", which_process);
    }
    else{
      int sshchild_to_parent, sshparent_to_child;
      int nbytes;
      char line[NI_MAXSERV + PASSPHRASE_SIZE*2 +1];
      char * hex_pp;

      if(key_dir == NULL){
        key_filename = key_base_filename;
      }
      else{
        key_filename = (char*)malloc(strlen(key_dir) + strlen(key_base_filename) + 2);
        sprintf(key_filename, "%s/%s", key_dir, key_base_filename);
      }

      //only allowing local -> remote for now
      char * colon_loc_first = strchr(argv[argc-2], ':');
      char * colon_loc_second = strchr(argv[argc-1], ':');
      char * colon_loc;
      int remote_arg_offset;

      if((colon_loc_first == NULL && colon_loc_second == NULL) || (colon_loc_first != NULL && colon_loc_second != NULL)){
        fprintf(stderr, "ERROR: Sorry, UDR only does local -> remote or remote -> local\n");
        exit(1);
      }
      else if(colon_loc_first != NULL){
        colon_loc = colon_loc_first;
        remote_to_local = true;
        remote_arg_offset = 2;
      }
      else{
        colon_loc = colon_loc_second;
        local_to_remote = true;
        remote_arg_offset = 1;
      }

      port_num = (char*) malloc(NI_MAXSERV);

      char * at_loc = strchr(argv[argc - remote_arg_offset], '@');

      //for now don't allow -l for the initial username just @, only works for when rsync calls it
      int username_len;
      if(at_loc == NULL){
        username = NULL;
        username_len = 0;
      }
      else{
        username_len = at_loc - argv[argc - remote_arg_offset] + 1;
        username = (char *) malloc(username_len);
        strncpy(username, argv[argc - remote_arg_offset], username_len - 1);
        username[username_len-1] = '\0';
      }

      int host_len = colon_loc - argv[argc - remote_arg_offset];
      host = (char *) malloc(host_len+1);
      strncpy(host, argv[argc - remote_arg_offset]+username_len, host_len-username_len);
      host[host_len-username_len] = '\0';


      char udr_args[20];
      if(!encryption)
        strcpy(udr_args, "-n ");
      else
        udr_args[0] = '\0';

      if(verbose_mode)
        strcat(udr_args, "-v ");

      strcat(udr_args, "-t rsync");

      if(verbose_mode){
        fprintf(stderr, "%s username: '%s' host: '%s'\n", which_process, username, host);
      }

      char* udr_cmd = (char *) malloc(strlen(udr_program_dest) + strlen(udr_args) + 3);
      sprintf(udr_cmd, "%s %s", udr_program_dest, udr_args);

      run_ssh(host, username, udr_cmd, &sshparent_to_child, &sshchild_to_parent);

      nbytes = read(sshchild_to_parent, line, NI_MAXSERV+PASSPHRASE_SIZE*2+1);

      if(verbose_mode){
        fprintf(stderr, "%s Received string: %s\n", which_process, line);
      }

      if(nbytes <= 0){
        fprintf(stderr, "udr: unexpected response from server, exiting.\n");
        exit(-1);
      }

      port_num = strtok(line, " ");
      hex_pp = strtok(NULL, " ");

      if(verbose_mode){
        fprintf(stderr, "%s port_num: %s passphrase: %s\n", which_process, port_num, hex_pp);
      }

      FILE *key_file = fopen(key_filename, "w");
      int succ = chmod(key_filename, S_IRUSR|S_IWUSR);

      if(key_file == NULL){
        fprintf(stderr, "ERROR: could not write key file: %s\n", key_filename);
        exit(-1);
      }
      fprintf(key_file, "%s", hex_pp);
      fclose(key_file);

      //make sure the port num str is null terminated 
      char * ptr;
      if((ptr = strchr(port_num, '\n')) != NULL)
        *ptr = '\0';

      int rsync_argc = argc - rsync_arg_idx + 4; //need two more spots

      char ** rsync_argv;
      rsync_argv = (char**) malloc(sizeof(char *) * rsync_argc);

      int rsync_idx = 0;
      for(int i = rsync_arg_idx; i < argc-2; i++){
        rsync_argv[rsync_idx] = (char*)malloc(strlen(argv[i])+1);
        rsync_argv[rsync_idx] = argv[i];
        rsync_idx++;
      }
      //cerr << "done copying." << endl;
      rsync_argv[rsync_idx] = "--blocking-io";
      rsync_idx++;

      rsync_argv[rsync_idx] = "-e";
      rsync_idx++;

      char udr_rsync_args1[20];

      if(!encryption)
        strcpy(udr_rsync_args1, "-n ");
      else
        udr_rsync_args1[0] = '\0';

      if(verbose_mode)
        strcat(udr_rsync_args1, "-v ");

      strcat(udr_rsync_args1, "-s");

      const char * udr_rsync_args2 = "-p";

      rsync_argv[rsync_idx] = (char*) malloc(strlen(udr_program_src) + strlen(udr_rsync_args1) + strlen(port_num) + strlen(udr_rsync_args2) + strlen(key_filename) + 6);
      sprintf(rsync_argv[rsync_idx], "%s %s %s %s %s", udr_program_src, udr_rsync_args1, port_num, udr_rsync_args2, key_filename);

      rsync_idx++;
      rsync_argv[rsync_idx] = argv[argc-2];
      rsync_idx++;
      rsync_argv[rsync_idx] = argv[argc-1];
      rsync_idx++;
      rsync_argv[rsync_idx] = NULL;

      int child_to_parent, parent_to_child;

      pid_t local_rsync_pid = run_rsync(rsync_argv, &parent_to_child, &child_to_parent);
      if(verbose_mode)
        fprintf(stderr, "%s rsync pid: %d\n", which_process, local_rsync_pid);

      //at this point this process should wait for the rsync process to end
      int buf_size = 4096;
      char rsync_out_buf[buf_size];
      int bytes_read, bytes_written;

      //This prints out the stdout from rsync to stdout
      while((bytes_read = read(child_to_parent, rsync_out_buf, buf_size)) > 0){
        bytes_written = write(STDOUT_FILENO, rsync_out_buf, bytes_read);
      }

    }
  }


