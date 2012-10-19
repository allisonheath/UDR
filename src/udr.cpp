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
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

#include <udt.h>
#include "crypto.h"
#include "cc.h"
#include "udr_threads.h"
#include "udr_processes.h"
#include "udr.h"

using namespace std;

//Need a better way to handle global parameters/options
bool verbose_mode = false;
bool encryption = false;
bool is_daemon = false;

char *ssh_program = "ssh";
const char *rsync_program = "rsync";
char *key_base_filename = ".udr_key";
const char * which_process;

char udr_program_src[PATH_MAX];
char * udr_program_dest = NULL;

int default_start_port = 9000;
int default_end_port = 9100;

#define PORT "3490"  // the port users will be connecting to

#define BACKLOG 10     // how many pending connections queue will hold

void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int run_as_daemon(char * dir){
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener

            char ls_results[200];
            int lsparent_to_child, lschild_to_parent;
            fork_execvp("ls", NULL, &lsparent_to_child, &lschild_to_parent);
            int nbytes;
            while((nbytes = read(lschild_to_parent, ls_results, sizeof(ls_results)-1)) != 0){
              ls_results[nbytes] = '\0';
              printf("%s", ls_results);
            }

            if (send(new_fd, "Hello, world!", 13, 0) == -1)
                perror("send");
            close(new_fd);
            exit(0);
        }
        close(new_fd);  // parent doesn't need this
    }

    return 0;
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
  char * daemon_dir = NULL;
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
      is_daemon = true;
      daemon_dir = optarg;
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

    //now for daemon mode
    if(is_daemon){
      return run_as_daemon(daemon_dir);
    }
    else{
      if(tflag){
        run_receiver(default_start_port, default_end_port, rsync_program, encryption, verbose_mode);
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

      //use colons to determine whether local->remote or remote->local
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


        char udr_args[100];
        if(encryption)
          strcpy(udr_args, "-n ");
        else
          udr_args[0] = '\0';

        if(verbose_mode)
          strcat(udr_args, "-v");

        char udr_ports[50];
        sprintf(udr_args, "%s -a %d -b %d %s", udr_args, default_start_port, default_end_port, "-t rsync");

        if(verbose_mode){
          fprintf(stderr, "%s username: '%s' host: '%s'\n", which_process, username, host);
        }

        char* udr_cmd = (char *) malloc(strlen(udr_program_dest) + strlen(udr_args) + 3);
        sprintf(udr_cmd, "%s %s", udr_program_dest, udr_args);

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

      if(encryption)
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
}


