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

#ifndef UDR_PRODUCER_CONSUMER_H
#define UDR_PRODUCER_CONSUMER_H

#include "udr_threads.h"

#define num_encryption_threads 3

struct sender_context {
    char *outdata;

    int *bytes_read;

    pthread_cond_t wait;
    pthread_cond_t done;

    pthread_mutex_t wait_mutex;
    pthread_mutex_t done_mutex;

    bool readable;
    bool writable;
};

struct encrypter_context {
    char plain[max_block_size];
    char encrypted[max_block_size];

    crypto *crypt;

    int bytes_read;

    bool ready_to_encrypt;

    pthread_mutex_t mutex;
    pthread_cond_t encrypt_wait;

    pthread_cond_t *send_wait;

    bool *readable;
};

struct read_args {
    struct sender_context *sender_info;
    int num_threads;

    struct encrypter_context *encrypters;

    int fd;

    // syncronization info to prevent looping while all encryption
    // threads are occupied
    pthread_mutex_t mutex;
    pthread_cond_t wait;
};

struct send_args {
    struct sender_context *sender_info;
    int num_threads;

    UDTSOCKET * udt_socket;
};

void* run_threaded_encryption(crypto *crypt, int fd, UDTSOCKET * udt_socket);

//void* run_threaded_decryption(crypto *crypt, int fd, UDTSOCKET * udt_socket);


#endif
