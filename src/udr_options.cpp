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
 **********************[*******************************************************/

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <stdio.h>
#include <getopt.h>
#include <limits.h>
#include "udr_options.h"

#include <sys/stat.h>
#include <sys/types.h>

using namespace std;

void usage() {
    fprintf(stderr, "usage: udr [-n] [-v] [-a starting port number] [-b ending port number] [-c remote udr location] rsync [rsync options]\n");
    exit(1);
}

void set_default_udr_options(UDR_Options * options) {
    options->start_port = 9000;
    options->end_port = 9100;
    options->timeout = 15;

    options->tflag = false;
    options->sflag = false;
    options->verbose = false;
    options->encryption = false;
    options->server = false;
    options->version_flag = false;

    options->udr_program_src = (char*) malloc(PATH_MAX);
    options->udr_program_dest = "udr";
    options->ssh_program = "ssh";
    options->rsync_program = "rsync";
    options->rsync_timeout = "--timeout=15";
    options->key_base_filename = ".udr_key";
    options->key_filename = NULL;
    options->username = NULL;
    options->which_process = NULL;
    options->version = NULL;
    options->server_dir = NULL;
    options->server_port = "3490";
}

int get_udr_options(UDR_Options * udr_options, int argc, char * argv[], int rsync_arg_idx) {
    int ch;
    char *key_dir = NULL;

    set_default_udr_options(udr_options);

    strcpy(udr_options->udr_program_src, argv[0]);

    static struct option long_options[] = {
        {"verbose", no_argument, NULL, 'v'},
        {"version", no_argument, NULL, 0},
        {"start-port", required_argument, NULL, 'a'},
        {"end-port", required_argument, NULL, 'b'},
        {"receiver", no_argument, NULL, 't'},
        {"server", required_argument, NULL, 'd'},
        {"encrypt", no_argument, NULL, 'n'},
        {"sender", no_argument, NULL, 's'},
        {"login-name", required_argument, NULL, 'l'},
        {"keyfile", required_argument, NULL, 'p'},
        {"keydir", required_argument, NULL, 'k'},
        {"remote-udr", required_argument, NULL, 'c'},
        {"server-port", required_argument, NULL, 'o'},
        {"file", required_argument, NULL, 'f'},
        {0, 0, 0, 0}
    };

    int option_index = 0;

    while ((ch = getopt_long(rsync_arg_idx, argv, "tlnva:b:d:s:h:p:c:k:o:", long_options, &option_index)) != -1)
        switch (ch) {
            case 'a':
                udr_options->start_port = atoi(optarg);
                break;
            case 'b':
                udr_options->end_port = atoi(optarg);
                break;
            case 't':
                udr_options->tflag = 1;
                break;
            case 'd':
                udr_options->server = true;
                udr_options->server_dir = new char[PATH_MAX + 1];
                realpath(optarg, udr_options->server_dir);

                if (udr_options->server_dir == NULL) {
                    fprintf(stderr, "udr: error: could not resolve path %s\n", optarg);
                    exit(1);
                }
                struct stat st;
                if (stat(udr_options->server_dir, &st) != 0) {
                    fprintf(stderr, "udr: error: directory %s is not present\n", udr_options->server_dir);
                    exit(1);
                }

                if (!S_ISDIR(st.st_mode)) {
                    fprintf(stderr, "udr: error: %s is not a directory\n", udr_options->server_dir);
                    exit(1);
                }

                break;
            case 'n':
                udr_options->encryption = true;
                break;
            case 's':
                udr_options->sflag = 1;
                udr_options->port_num = optarg;
                break;
            case 'l':
                udr_options->username = optarg;
                break;
            case 'p':
                udr_options->key_filename = optarg;
                break;
            case 'c':
                udr_options->udr_program_dest = optarg;
                break;
            case 'k':
                key_dir = optarg;
                break;
            case 'v':
                udr_options->verbose = true;
                break;
            case 'o':
                udr_options->server_port = optarg;
            case 0:
                if (strcmp("version", long_options[option_index].name) == 0) {
                    udr_options->version_flag = true;
                }
                break;
            default:
                fprintf(stderr, "Illegal argument: %c\n", ch);
                usage();
        }

    //Finish setting up the key file path
    if (key_dir == NULL) {
        udr_options->key_filename = udr_options->key_base_filename;
    } else {
        udr_options->key_filename = (char*) malloc(strlen(key_dir) + strlen(udr_options->key_base_filename) + 2);
        sprintf(udr_options->key_filename, "%s/%s", key_dir, udr_options->key_base_filename);
    }

    //Set which_process for debugging output
    if (udr_options->verbose) {
        if (udr_options->sflag)
            udr_options->which_process = "Sender:";
        else if (udr_options->tflag)
            udr_options->which_process = "Receiver:";
        else
            udr_options->which_process = "Original:";

        fprintf(stderr, "%s Local program: %s Remote program: %s Encryption: %d\n", udr_options->which_process, udr_options->udr_program_src, udr_options->udr_program_dest, udr_options->encryption);
    }

    return 1;
}