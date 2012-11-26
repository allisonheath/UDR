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
#include <getopt.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <udt.h>
#include "crypto.h"
#include "cc.h"
#include "udr_threads.h"
#include "udr_server.h"
#include "udr_options.h"
#include "version.h"

using namespace std;

char * get_udr_cmd(UDR_Options * udr_options) {
    char udr_args[PATH_MAX];
    if (udr_options->encryption)
        strcpy(udr_args, "-n ");
    else
        udr_args[0] = '\0';

    if (udr_options->verbose)
        strcat(udr_args, "-v");

    sprintf(udr_args, "%s -a %d -b %d %s", udr_args, udr_options->start_port, udr_options->end_port, "-t rsync");

    char* udr_cmd = (char *) malloc(strlen(udr_options->udr_program_dest) + strlen(udr_args) + 3);
    sprintf(udr_cmd, "%s %s", udr_options->udr_program_dest, udr_args);

    return udr_cmd;
}

void print_version() {
    fprintf(stderr, "UDR version %s\n", version);
}

//only going to go from local -> remote and remote -> local, remote <-> remote maybe later, but local -> local doesn't make sense for UDR
int main(int argc, char* argv[]) {
    int use_rsync, rsync_arg_idx;
    use_rsync = 0;
    rsync_arg_idx = -1;
    
    char * host = NULL;
    
    bool local_to_remote, remote_to_local;
    local_to_remote = remote_to_local = false;

    if (argc < 1)
        usage();

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "rsync") == 0) {
            use_rsync = 1;
            rsync_arg_idx = i;
            break;
        }
    }

    if (!use_rsync) {
        rsync_arg_idx = argc;
    }

    //now get the options using udr_options.
    struct UDR_Options curr_options;
    get_udr_options(&curr_options, argc, argv, rsync_arg_idx);

    if (curr_options.version_flag)
        print_version();

    if (!use_rsync)
        usage();

    if (curr_options.tflag) {
        run_receiver(&curr_options);
        if (curr_options.verbose)
            fprintf(stderr, "%s run_receiver done\n", curr_options.which_process);
        exit(0);
    }//now for server mode
    else if (curr_options.server) {
        return run_as_server(&curr_options);
    } 
    
    else if (curr_options.sflag) {
        string arguments = "";
        string sep = " ";
        char** rsync_args = &argv[rsync_arg_idx];
        int rsync_argc = argc - rsync_arg_idx;
        char hex_pp[HEX_PASSPHRASE_SIZE];
        unsigned char passphrase[PASSPHRASE_SIZE];

        if (curr_options.encryption) {
            if (curr_options.verbose)
                fprintf(stderr, "%s Key filename: %s\n", curr_options.which_process, curr_options.key_filename);
            FILE* key_file = fopen(curr_options.key_filename, "r");
            if (key_file == NULL) {
                fprintf(stderr, "ERROR: could not read from key_file %s\n", curr_options.key_filename);
                exit(-1);
            }
            fscanf(key_file, "%s", hex_pp);
            fclose(key_file);
            remove(curr_options.key_filename);

            for (unsigned int i = 0; i < strlen(hex_pp); i = i + 2) {
                unsigned int c;
                sscanf(&hex_pp[i], "%02x", &c);
                passphrase[i / 2] = (unsigned char) c;
            }
        }

        host = argv[rsync_arg_idx - 1];

        if (curr_options.verbose)
            fprintf(stderr, "%s Host: %s\n", curr_options.which_process, host);

        for (int i = 0; i < rsync_argc; i++) {
            if (curr_options.verbose)
                fprintf(stderr, "%s rsync arg[%d]: %s\n", curr_options.which_process, i, rsync_args[i]);

            //hack for when no directory is specified -- because strtok is lame, probably should write own tokenizer, but this will do for now
            if (strlen(rsync_args[i]) == 0)
                arguments += ".";
            else
                arguments += rsync_args[i];

            arguments += sep;
        }

        //fprintf(stderr, "rsync cmd: '%s'\n", arguments.c_str());

        run_sender(host, &curr_options, passphrase, arguments.c_str(), rsync_argc, rsync_args);

        if (curr_options.verbose)
            fprintf(stderr, "%s run_sender done\n", curr_options.which_process);
    } else {
        char ** sources = (char**) malloc(argc * sizeof (char*));
        char ** server_sources;
        char * first_source = NULL;
        char * dest = NULL;
        int source_idx = 0;
        int first_source_idx = -1;
        int dest_idx = -1;

        /* Get username, host, and remote udr cmd */
        for (int i = rsync_arg_idx + 1; i < argc; i++) {
            if (argv[i][0] == '-')
                continue;

            if (first_source_idx == -1) {
                first_source = argv[i];
                first_source_idx = i;
            }

            sources[source_idx] = (char*) malloc(strlen(argv[i]) * sizeof (char) + 1);
            strcpy(sources[source_idx], argv[i]);
            source_idx++;
        }

        //Only given a source
        if (source_idx == 1) {
            dest = NULL;
            dest_idx = -1;
        } else {
            dest = argv[argc - 1];
            dest_idx = argc - 1;
            source_idx--;
        }

        if (first_source_idx == -1) {
            usage();
        }

        if (curr_options.verbose) {
            if (dest_idx == -1)
                fprintf(stderr, "%s Source: %s No Destination\n", curr_options.which_process, argv[first_source_idx]);
            else
                fprintf(stderr, "%s Source: %s Destination: %s\n", curr_options.which_process, argv[first_source_idx], argv[dest_idx]);
        }

        //use colons to determine whether local->remote or remote->local
        char * colon_loc_first = strchr(argv[first_source_idx], ':');
        char * colon_loc_second = NULL;

        int max_length;
        if (dest_idx == -1 || strlen(argv[first_source_idx]) > strlen(argv[dest_idx]))
            max_length = strlen(argv[first_source_idx]);
        else
            max_length = strlen(argv[dest_idx]);

        char remote_arg[max_length];

        if (dest_idx != -1)
            colon_loc_second = strchr(argv[dest_idx], ':');

        //int remote_arg_idx;

        if ((colon_loc_first == NULL && colon_loc_second == NULL) || (colon_loc_first != NULL && colon_loc_second != NULL)) {
            fprintf(stderr, "udr error: Sorry, UDR only does local -> remote or remote -> local\n");
            exit(1);
        }//Need to fix for server.
        else if (colon_loc_first != NULL) {
            //only allowed to use double colon in source -- check
            if (strlen(colon_loc_first) > 1 && colon_loc_first[1] == ':') {
                if (curr_options.verbose) {
                    fprintf(stderr, "Removing second colon: %s\n", colon_loc_first);
                }
                //remove the first colon -- destructive of argv[first_source_idx]...
                colon_loc_first[0] = '\0';
                *colon_loc_first++;
                strcpy(remote_arg, argv[first_source_idx]);
                strcat(remote_arg, colon_loc_first);

                //now do for the sources
                server_sources = (char**) malloc(source_idx * sizeof (char*));
                for (int i = 0; i < source_idx; i++) {
                    server_sources[i] = (char*) malloc(strlen(sources[i]) + 1);
                    char * source_colon_loc = strchr(sources[i], ':');
                    source_colon_loc[0] = '\0';
                    *source_colon_loc++;
                    strcpy(server_sources[i], sources[i]);
                    strcat(server_sources[i], source_colon_loc);
                }
                curr_options.server = true;
            } else {
                strcpy(remote_arg, argv[first_source_idx]);
            }

            first_source = remote_arg;
            remote_to_local = true;
        } else {
            local_to_remote = true;
            strcpy(remote_arg, argv[dest_idx]);
            dest = remote_arg;
        }

        char * colon_loc = strchr(remote_arg, ':');

        if (curr_options.verbose) {
            fprintf(stderr, "%s remote_arg: %s\n", curr_options.which_process, remote_arg);
        }

        curr_options.port_num = (char*) malloc(NI_MAXSERV);

        char * at_loc = strchr(remote_arg, '@');

        //for now don't allow -l for the initial username just @, only works for when rsync calls it
        int username_len;
        if (at_loc == NULL) {
            curr_options.username = NULL;
            username_len = 0;
        } else {
            username_len = at_loc - remote_arg + 1;
            curr_options.username = (char *) malloc(username_len);
            strncpy(curr_options.username, remote_arg, username_len - 1);
            curr_options.username[username_len - 1] = '\0';
        }

        int host_len = colon_loc - remote_arg;
        host = (char *) malloc(host_len + 1);
        strncpy(host, remote_arg + username_len, host_len - username_len);
        host[host_len - username_len] = '\0';

        char * udr_cmd = get_udr_cmd(&curr_options);

        if (curr_options.verbose) {
            fprintf(stderr, "%s username: '%s' host: '%s'\n", curr_options.which_process, curr_options.username, host);
        }

        int line_size = NI_MAXSERV + PASSPHRASE_SIZE * 2 + 1;
        char * line = (char*) malloc(line_size);
        line[0] = '\0';

        /* if given double colons then use the server connection */
        if (curr_options.server) {
            int server_exists = get_server_connection(host, curr_options.server_port, udr_cmd, line, line_size);
            if (!server_exists) {
                fprintf(stderr, "ERROR: Cannot connect to server at %s:%s\n", host, curr_options.server_port);
                exit(1);
            }
        }/* If not try ssh */
        else {
            int sshchild_to_parent, sshparent_to_child;
            int nbytes;

            int ssh_argc;
            if (curr_options.username)
                ssh_argc = 6;
            else
                ssh_argc = 5;

            char ** ssh_argv;
            ssh_argv = (char**) malloc(sizeof (char *) * ssh_argc);

            int ssh_idx = 0;
            ssh_argv[ssh_idx++] = curr_options.ssh_program;
            if (curr_options.username) {
                ssh_argv[ssh_idx++] = "-l";
                ssh_argv[ssh_idx++] = curr_options.username;
            }
            ssh_argv[ssh_idx++] = host;
            ssh_argv[ssh_idx++] = udr_cmd;
            ssh_argv[ssh_idx++] = NULL;

            if (curr_options.verbose) {
                fprintf(stderr, "ssh_program %s\n", curr_options.ssh_program);
                for (int i = 0; i < ssh_idx; i++) {
                    fprintf(stderr, "ssh_argv[%d]: %s\n", i, ssh_argv[i]);
                }
            }

            fork_execvp(curr_options.ssh_program, ssh_argv, &sshparent_to_child, &sshchild_to_parent);

            nbytes = read(sshchild_to_parent, line, line_size);

            if (curr_options.verbose) {
                fprintf(stderr, "%s Received string: %s\n", curr_options.which_process, line);
            }

            if (nbytes <= 0) {
                fprintf(stderr, "udr: unexpected response from server, exiting.\n");
                exit(1);
            }
        }
        /* Now do the exact same thing no matter whether server or ssh process */

        if (strlen(line) == 0) {
            fprintf(stderr, "udr: unexpected response from server, exiting.\n");
            exit(1);
        }

        curr_options.port_num = strtok(line, " ");
        char * hex_pp = strtok(NULL, " ");

        if (curr_options.verbose) {
            fprintf(stderr, "%s port_num: %s passphrase: %s\n", curr_options.which_process, curr_options.port_num, hex_pp);
        }

        if (curr_options.encryption) {
            FILE *key_file = fopen(curr_options.key_filename, "w");
            int succ = chmod(curr_options.key_filename, S_IRUSR | S_IWUSR);

            if (key_file == NULL) {
                fprintf(stderr, "ERROR: could not write key file: %s\n", curr_options.key_filename);
                exit(-1);
            }
            fprintf(key_file, "%s", hex_pp);
            fclose(key_file);
        }

        //make sure the port num str is null terminated 
        char * ptr;
        if ((ptr = strchr(curr_options.port_num, '\n')) != NULL)
            *ptr = '\0';

        int rsync_argc = argc - rsync_arg_idx + 5; //need more spots

        char ** rsync_argv;
        rsync_argv = (char**) malloc(sizeof (char *) * rsync_argc);

        int rsync_idx = 0;
        rsync_argv[rsync_idx] = (char*) malloc(strlen(argv[0]) + 1);
        strcpy(rsync_argv[rsync_idx], argv[rsync_arg_idx]);
        rsync_idx++;


        //cerr << "done copying." << endl;
        rsync_argv[rsync_idx++] = "--blocking-io";

        rsync_argv[rsync_idx++] = curr_options.rsync_timeout;

        rsync_argv[rsync_idx++] = "-e";

        char udr_rsync_args1[20];

        if (curr_options.encryption)
            strcpy(udr_rsync_args1, "-n ");
        else
            udr_rsync_args1[0] = '\0';

        if (curr_options.verbose)
            strcat(udr_rsync_args1, "-v ");

        strcat(udr_rsync_args1, "-s");

        const char * udr_rsync_args2 = "-p";

        //printf("udr_program_src: %s\n", udr_program_src);
        //printf("udr_rsync_args1: %s\n", udr_rsync_args1);
        //printf("port_num: %s\n", port_num);
        //printf("udr_rsync_args2 %s\n", udr_rsync_args2);
        //printf("key_filename %s\n", key_filename);

        rsync_argv[rsync_idx] = (char*) malloc(strlen(curr_options.udr_program_src) + strlen(udr_rsync_args1) + strlen(curr_options.port_num) + strlen(udr_rsync_args2) + strlen(curr_options.key_filename) + 6);
        sprintf(rsync_argv[rsync_idx], "%s %s %s %s %s", curr_options.udr_program_src, udr_rsync_args1, curr_options.port_num, udr_rsync_args2, curr_options.key_filename);

        rsync_idx++;

        //fprintf(stderr, "first_source_idx: %d\n", first_source_idx);
        for (int i = rsync_arg_idx + 1; i < first_source_idx; i++) {
            rsync_argv[rsync_idx] = (char*) malloc(strlen(argv[i]) + 1);
            rsync_argv[rsync_idx] = argv[i];
            rsync_idx++;
        }

        for (int i = 0; i < source_idx; i++) {
            if (curr_options.server)
                rsync_argv[rsync_idx++] = server_sources[i];
            else
                rsync_argv[rsync_idx++] = sources[i];
        }

        if (dest_idx != -1) {
            rsync_argv[rsync_idx++] = dest;
        }

        rsync_argv[rsync_idx] = NULL;

        int parent_to_child, child_to_parent;

        pid_t local_rsync_pid = fork_execvp(curr_options.rsync_program, rsync_argv, &parent_to_child, &child_to_parent);
        if (curr_options.verbose)
            fprintf(stderr, "%s rsync pid: %d\n", curr_options.which_process, local_rsync_pid);

        //at this point this process should wait for the rsync process to end
        int buf_size = 4096;
        char rsync_out_buf[buf_size];
        int bytes_read, bytes_written;

        //This prints out the stdout from rsync to stdout
        while ((bytes_read = read(child_to_parent, rsync_out_buf, buf_size)) > 0) {
            bytes_written = write(STDOUT_FILENO, rsync_out_buf, bytes_read);
        }
    }

}


