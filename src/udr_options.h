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

#ifndef UDR_OPTIONS_H
#define UDR_OPTIONS_H
#include <string>
#include <netdb.h>
#include <limits.h>

struct UDR_Options{
    int start_port;
    int end_port;
    int timeout;

    bool tflag;
    bool sflag;
    bool verbose;
    bool encryption;
    //bool server;
    bool version_flag;
    bool server_connect;

    char udr_program_src[PATH_MAX+1];
    char udr_program_dest[PATH_MAX+1];
    char ssh_program[PATH_MAX+1];
    char rsync_program[PATH_MAX+1];
    char rsync_timeout[PATH_MAX+1]; 
    char shell_program[PATH_MAX+1];
    
    char key_base_filename[PATH_MAX+1];
    char key_filename[PATH_MAX+1];
    
    char host[PATH_MAX+1];
    char port_num[NI_MAXSERV+1];
    char username[PATH_MAX+1];
    char which_process[PATH_MAX+1];
    char version[PATH_MAX+1];
    char server_dir[PATH_MAX+1];
    char server_port[NI_MAXSERV+1];

    char server_config[PATH_MAX+1];

    uid_t rsync_uid;
    gid_t rsync_gid;
    
};

void usage();

int get_udr_options(UDR_Options * options, int argc, char * argv[], int rsync_arg_idx);

void get_host_username(UDR_Options * udr_options, int argc, char *argv[], int rsync_arg_idx);

#endif