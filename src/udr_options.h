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

struct UDR_Options{
    int start_port;
    int end_port;
    int timeout;

    bool tflag;
    bool sflag;
    bool verbose;
    bool encryption;
    bool server;
    bool version_flag;

    char *udr_program_src;
    char *udr_program_dest;
    char *ssh_program;
    char *rsync_program;
    char *rsync_timeout;
    char *shell_program;
    
    char *key_base_filename;
    char *key_filename;
    
    char *host;
    char *port_num;
    char *username;
    const char *which_process;
    char *version;
    char *server_dir;
    char *server_port;
    
};

void usage();


int get_udr_options(UDR_Options * options, int argc, char * argv[], int rsync_arg_idx);

void get_host_username(UDR_Options * udr_options, int argc, char *argv[], int rsync_arg_idx);

#endif