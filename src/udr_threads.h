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

#ifndef UDR_THREADS_H
#define UDR_THREADS_H

#include "crypto.h"

const int max_block_size = 64*1024; //what should this be? maybe based on UDT buffer size?
 
struct thread_data{
  UDTSOCKET * udt_socket;
  int fd;
  int id;
  crypto * crypt;
  bool log;
  string logfile_dir;
  bool is_complete;
};

void *handle_to_udt(void *threadarg);
void *udt_to_handle(void *threadarg);

int run_sender(char* receiver, char* receiver_port, bool encryption, unsigned char * passphrase, bool verbose_mode, const char* cmd, int argc, char ** argv);
int run_receiver(int start_port, int end_port, const char * rsync_program, bool encryption, bool verbose_mode);

#endif