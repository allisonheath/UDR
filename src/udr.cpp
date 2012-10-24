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
#include <sstream>
#include <limits.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <udt.h>
#include "crypto.h"
#include "cc.h"
#include "udr_threads.h"
#include "udr_server.h"

using namespace std;

//Need a better way to handle global parameters/options
bool verbose_mode = false;
bool encryption = false;
bool is_server = false;

char *ssh_program = "ssh";
const char *rsync_program = "rsync";
char *key_base_filename = ".udr_key";
const char * which_process;

char * server_port = "3490";
char * rsync_timeout = "--timeout=15";

char udr_program_src[PATH_MAX];
char * udr_program_dest = NULL;

int default_start_port = 9000;
int default_end_port = 9100;

char * get_udr_cmd(){
  char udr_args[100];
  if(encryption)
    strcpy(udr_args, "-n ");
  else
    udr_args[0] = '\0';

  if(verbose_mode)
    strcat(udr_args, "-v");

  char udr_ports[50];
  sprintf(udr_args, "%s -a %d -b %d %s", udr_args, default_start_port, default_end_port, "-t rsync");


  char* udr_cmd = (char *) malloc(strlen(udr_program_dest) + strlen(udr_args) + 3);
  sprintf(udr_cmd, "%s %s", udr_program_dest, udr_args);
  return udr_cmd;
}


void usage(){
  fprintf(stderr, "usage: udr [-n] [-v] [-a starting port number] [-b ending port number] [-c remote udr location] rsync [rsync options]\n");
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
  char * server_dir = NULL;
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

  //only with rsync
  if(!use_rsync)
    usage();
  
  while((ch = getopt(rsync_arg_idx, argv, "tlnva:b:d:s:h:p:c:k:")) != -1)
    switch (ch) {
      case 'a':
      default_start_port = atoi(optarg);
      break;
      case 'b':
      default_end_port = atoi(optarg);
      break;
      case 't':
      tflag = 1;
      break;
      case 'd':
      is_server = true;
      server_dir = new char[PATH_MAX+1];
      realpath(optarg, server_dir);

      if(server_dir == NULL){
        fprintf(stderr, "udr: error: could not resolve path %s\n", optarg);
        exit(1);
      }
      struct stat st;
      if(stat(server_dir,&st) != 0){
        fprintf(stderr, "udr: error: directory %s is not present\n", server_dir);
        exit(1);
      }

      if(!S_ISDIR(st.st_mode)){
        fprintf(stderr, "udr: error: %s is not a directory\n", server_dir);
        exit(1);
      }


      break;
      case 'n':
      encryption = true;
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
        run_receiver(default_start_port, default_end_port, rsync_program, encryption, verbose_mode, is_server, server_dir);
        if(verbose_mode)
          fprintf(stderr, "%s run_receiver done\n", which_process);
        exit(0);
      }
      //now for server mode
      else if(is_server){
        return run_as_server(server_dir, server_port, udr_program_dest);
      }
      else if(sflag){
        string arguments = "";
        string sep = " ";
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

          //hack for when no directory is specified -- because strtok is lame, probably should write own tokenizer, but this will do for now
          if(strlen(rsync_args[i]) == 0)
            arguments += ".";
          else
            arguments += rsync_args[i];

          arguments += sep;
        }

        //fprintf(stderr, "rsync cmd: '%s'\n", arguments.c_str());

        run_sender(host, port_num, encryption, passphrase, verbose_mode, arguments.c_str(), rsync_argc, rsync_args);

        if(verbose_mode)
          fprintf(stderr, "%s run_sender done\n", which_process);
      }
      else{
        char * source = NULL;
        char * dest = NULL;
        int source_idx = -1;
        int dest_idx = -1;

        /* Get username, host, and remote udr cmd */
        for(int i = rsync_arg_idx+1; i < argc; i++){
          if(argv[i][0] == '-')
            continue;
          if(source_idx == -1){
            source = argv[i];
            source_idx = i;
          }
          else{
            dest = argv[i];
            dest_idx = i;
            if(i != argc-1){
              fprintf(stderr, "WARNING: Ignoring arguments after %s\n", argv[dest_idx]);
            }
            break;
          }
        }

        if(source_idx == -1){
          fprintf(stderr, "ERROR: no source specified\n");
          exit(1);
        }

        if(verbose_mode){
          if(dest_idx == -1)
            fprintf(stderr, "%s Source: %s No Destination\n", which_process, argv[source_idx]);
          else
            fprintf(stderr, "%s Source: %s Destination: %s\n", which_process, argv[source_idx], argv[dest_idx]);
        }

        //use colons to determine whether local->remote or remote->local
        char * colon_loc_first = strchr(argv[source_idx], ':');
        char * colon_loc_second = NULL;

        int max_length;
        if(dest_idx == -1 || strlen(argv[source_idx]) > strlen(argv[dest_idx]))
          max_length = strlen(argv[source_idx]);
        else
          max_length = strlen(argv[dest_idx]);

        char remote_arg[max_length];

        if(dest_idx != -1)
          colon_loc_second = strchr(argv[dest_idx], ':');

        //int remote_arg_idx;

        if((colon_loc_first == NULL && colon_loc_second == NULL) || (colon_loc_first != NULL && colon_loc_second != NULL)){
          fprintf(stderr, "ERROR: Sorry, UDR only does local -> remote or remote -> local\n");
          exit(1);
        }
        else if(colon_loc_first != NULL){
          //only allowed to use double colon in first slot -- check
          if(strlen(colon_loc_first) > 1 && colon_loc_first[1] == ':'){
            //remove the first colon -- destructive of argv[source_idx]...
            colon_loc_first[0] = '\0';
            *colon_loc_first++;
            strcpy(remote_arg, argv[source_idx]);
            strcat(remote_arg, colon_loc_first);
            is_server = true;
          }
          else{
            strcpy(remote_arg, argv[source_idx]);
          }

          source = remote_arg;
          remote_to_local = true;
        }
        else{
          local_to_remote = true;
          strcpy(remote_arg, argv[dest_idx]);
          dest = remote_arg;
        }

        char * colon_loc = strchr(remote_arg, ':');

        if(verbose_mode){
          fprintf(stderr, "%s remote_arg: %s\n", which_process, remote_arg);
        }

        port_num = (char*) malloc(NI_MAXSERV);

        char * at_loc = strchr(remote_arg, '@');

      //for now don't allow -l for the initial username just @, only works for when rsync calls it
        int username_len;
        if(at_loc == NULL){
          username = NULL;
          username_len = 0;
        }
        else{
          username_len = at_loc - remote_arg + 1;
          username = (char *) malloc(username_len);
          strncpy(username, remote_arg, username_len - 1);
          username[username_len-1] = '\0';
        }

        int host_len = colon_loc - remote_arg;
        host = (char *) malloc(host_len+1);
        strncpy(host, remote_arg+username_len, host_len-username_len);
        host[host_len-username_len] = '\0';

        char * udr_cmd = get_udr_cmd();

        if(verbose_mode){
          fprintf(stderr, "%s username: '%s' host: '%s'\n", which_process, username, host);
        }

        if(key_dir == NULL){
          key_filename = key_base_filename;
        }
        else{
          key_filename = (char*)malloc(strlen(key_dir) + strlen(key_base_filename) + 2);
          sprintf(key_filename, "%s/%s", key_dir, key_base_filename);
        }

        
        int line_size = NI_MAXSERV + PASSPHRASE_SIZE*2 +1;
        char line[line_size];
        line[0] = '\0';

        /* if given double colons then use the server connection */
        if(is_server){
        int server_exists = get_server_connection(host, server_port, udr_cmd, line, line_size);
        if(!server_exists){
          fprintf(stderr, "ERROR: Cannot connect to server at %s:%s\n", host, server_port);
          exit(1);
        }
      }
        /* If not try ssh */
        else{
        int sshchild_to_parent, sshparent_to_child;
        int nbytes;

        int ssh_argc;
        if (username)
          ssh_argc = 5;
        else
          ssh_argc = 4;

        char ** ssh_argv;
        ssh_argv = (char**) malloc(sizeof(char *) * ssh_argc);

        int ssh_idx = 0;
        ssh_argv[ssh_idx++] = ssh_program;
        if(username){
          ssh_argv[ssh_idx++] = "-l";
          ssh_argv[ssh_idx++] = username;
        }
        ssh_argv[ssh_idx++] = host;
        ssh_argv[ssh_idx++] = udr_cmd;

        fork_execvp(ssh_program, ssh_argv, &sshparent_to_child, &sshchild_to_parent);

        nbytes = read(sshchild_to_parent, line, line_size);

        if(verbose_mode){
          fprintf(stderr, "%s Received string: %s\n", which_process, line);
        }

        if(nbytes <= 0){
          fprintf(stderr, "udr: unexpected response from server, exiting.\n");
          exit(1);
        }
        }
        /* Now do the exact same thing no matter whether server or ssh process */

        if(strlen(line) == 0){
          fprintf(stderr, "udr: unexpected response from server, exiting.\n");
          exit(1);
        }

        port_num = strtok(line, " ");
        char * hex_pp = strtok(NULL, " ");

        if(verbose_mode){
          fprintf(stderr, "%s port_num: %s passphrase: %s\n", which_process, port_num, hex_pp);
        }

        if(encryption){
          FILE *key_file = fopen(key_filename, "w");
          int succ = chmod(key_filename, S_IRUSR|S_IWUSR);

          if(key_file == NULL){
            fprintf(stderr, "ERROR: could not write key file: %s\n", key_filename);
            exit(-1);
          }
          fprintf(key_file, "%s", hex_pp);
          fclose(key_file);
        } 

      //make sure the port num str is null terminated 
        char * ptr;
        if((ptr = strchr(port_num, '\n')) != NULL)
          *ptr = '\0';

      int rsync_argc = argc - rsync_arg_idx + 5; //need more spots

      char ** rsync_argv;
      rsync_argv = (char**) malloc(sizeof(char *) * rsync_argc);

      int rsync_idx = 0;
      for(int i = rsync_arg_idx; i < argc-2; i++){
        rsync_argv[rsync_idx] = (char*)malloc(strlen(argv[i])+1);
        rsync_argv[rsync_idx] = argv[i];
        rsync_idx++;
      }
      //cerr << "done copying." << endl;
      rsync_argv[rsync_idx++] = "--blocking-io";

      rsync_argv[rsync_idx++] = rsync_timeout;

      rsync_argv[rsync_idx++] = "-e";

      char udr_rsync_args1[20];

      if(encryption)
        strcpy(udr_rsync_args1, "-n ");
      else
        udr_rsync_args1[0] = '\0';

      if(verbose_mode)
        strcat(udr_rsync_args1, "-v ");

      strcat(udr_rsync_args1, "-s");

      const char * udr_rsync_args2 = "-p";

      //printf("udr_program_src: %s\n", udr_program_src);
      //printf("udr_rsync_args1: %s\n", udr_rsync_args1);
      //printf("port_num: %s\n", port_num);
      //printf("udr_rsync_args2 %s\n", udr_rsync_args2);
      //printf("key_filename %s\n", key_filename);

      rsync_argv[rsync_idx] = (char*) malloc(strlen(udr_program_src) + strlen(udr_rsync_args1) + strlen(port_num) + strlen(udr_rsync_args2) + strlen(key_filename) + 6);
      sprintf(rsync_argv[rsync_idx], "%s %s %s %s %s", udr_program_src, udr_rsync_args1, port_num, udr_rsync_args2, key_filename);

      rsync_idx++;
      rsync_argv[rsync_idx++] = source;

      if(dest_idx != -1){
        rsync_argv[rsync_idx++] = dest;
      }

      rsync_argv[rsync_idx] = NULL;

      int parent_to_child, child_to_parent;

      pid_t local_rsync_pid = fork_execvp(rsync_program, rsync_argv, &parent_to_child, &child_to_parent);
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


