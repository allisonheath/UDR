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

struct ProducerConsumerContext{
    // synchronization
    pthread_cond_t* consumer_wait;
    pthread_cond_t* producer_wait;
    pthread_mutex_t* mutex;

    bool ready_to_read;
    bool ready_to_write;

    // data buffer
    char data[max_block_size];
    int bytes_read;

    // copied over from udr_threads
    crypto *crypt;
    int fd;
    UDTSOCKET * udt_socket;

};

void* run_threaded_encryption(crypto *crypt, int fd, UDTSOCKET * udt_socket);

void* run_threaded_decryption(crypto *crypt, int fd, UDTSOCKET * udt_socket);


#endif
