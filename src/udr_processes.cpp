/* Opens read and write pipes, not called popen2 because doesn't use sh */

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

using namespace std;

pid_t fork_execvp(const char *program, char* argv[], int * ptc, int * ctp){
  pid_t pid;

  int parent_to_child[2], child_to_parent[2];

  char* arg;
  int idx = 0;

  //need to figure out best way to do global parameters
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

int run_as_server(char * dir, char * port, char * udr_program_dest){
  int backlog = 10;
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

    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
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

    if (listen(sockfd, backlog) == -1) {
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

    printf("udr server: serving files from %s on port %s, waiting for connections...\n", dir, port);

    while(1) {  // main accept() loop
      sin_size = sizeof their_addr;
      new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
      if (new_fd == -1) {
        perror("accept");
        continue;
      }

      inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
      printf("udr server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            //close(sockfd); // child doesn't need the listener, now it does
            int numbytes;

            int buf_size = 200;
            int num_args = 10;

            char buf[buf_size];
            if((numbytes = recv(new_fd, buf, buf_size-1, 0)) == -1){
              perror("recv");
              exit(1);
            }

            buf[numbytes] = '\0';

            //printf("server: numbytes: %d received '%s'\n", numbytes, buf);
            //should check that udr command is actually udr command but for now let's just fork_execvp again
            char * tok = strtok (buf," ");

            //We're going to ignore the udr program that the client sends in this case for safety
            char * udr_program_client = tok;

            //Need to dead with this better
            char ** udr_argv = (char**) malloc(sizeof(char *) * num_args+2); 
            int idx = 0;
            udr_argv[idx++] = udr_program_dest;
            udr_argv[idx++] = "-d";
            udr_argv[idx++] = dir;
            do{
              tok = strtok(NULL, " ");
              udr_argv[idx++] = tok;
            } while(tok != NULL);

            int parent_to_child, child_to_parent;
            

            fork_execvp(udr_program_dest, udr_argv, &parent_to_child, &child_to_parent);

            //at this point this process should wait for the udr process to end
            char udr_out_buf[buf_size];
            int bytes_read, bytes_written;

            //This prints out the stdout from udr to stdout
            while((bytes_read = read(child_to_parent, udr_out_buf, buf_size)) > 0){
              //then send this info back to the client
              if(send(new_fd, udr_out_buf, buf_size-1, 0) == -1)
                perror("send");
            }

            exit(0);
          }
        close(new_fd);  // parent doesn't need this
      }

      return 0;
    }

    int get_server_connection(char * host, char * port, char * udr_cmd, char * line, int line_size){
   //first check to see udr server is running.... 

      int sockfd, numbytes;
      struct addrinfo hints, *servinfo, *p;
      int rv;
      char s[INET6_ADDRSTRLEN];

      memset(&hints, 0, sizeof hints);
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;

      if((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0){
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 0;
      }

      for(p = servinfo; p != NULL; p = p->ai_next){
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
          //perror("udr client: socket");
          continue;
        }

        if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
          close(sockfd);
          //perror("udr client: connect");
          continue;
        }

        break;
      }

      if(p == NULL){
        //fprintf(stderr, "udr error: failed to connect\n");
        return 0;
      }

      inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);

      //First send the udr command
      //printf("client should be sending: %s\n", udr_cmd);

      if(send(sockfd, udr_cmd, strlen(udr_cmd), 0) == -1){
        perror("udr send");
        exit(1);
      }

      freeaddrinfo(servinfo);

      if ((numbytes = recv(sockfd, line, line_size-1, 0)) == -1) {
        perror("udr recv");
        exit(1);
      }

      line[numbytes] = '\0';

      close(sockfd);

      return 1;
    }
