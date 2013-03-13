/*****************************************************************************
Copyright 2013 Laboratory for Advanced Computing at the University of Chicago

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
#include <pthread.h>
#include <udt.h>
#include "udr_threads.h"
#include "udr_producer_consumer.h"

void* run_threaded_encryption(crypto *crypt, int fd, UDTSOCKET * udt_socket)
{
    struct ProducerConsumerContext context;
    context.encrypt_wait = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
    context.send_wait = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
    context.mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    context.fd = fd;
    context.udt_socket = udt_socket;
    context.crypt = crypt;

    pthread_cond_init(context.encrypt_wait, NULL);
    pthread_cond_init(context.send_wait, NULL);
    pthread_mutex_init(context.mutex, NULL);

    pthread_t prod;
    pthread_t cons;

    if (pthread_create(&prod, NULL, encrypt_thread, (void*)&context) != 0) {
        fprintf(stderr, "couldn't create encrypt thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&cons, NULL, send_thread, (void*)&context) != 0) {
        fprintf(stderr, "Could not create send thread");
        pthread_join(prod, NULL);
        exit(EXIT_FAILURE);
    }

    pthread_join(prod, NULL);
    pthread_join(cons, NULL);

    pthread_mutex_destroy(context.mutex);
    pthread_cond_destroy(context.encrypt_wait);
    pthread_cond_destroy(context.send_wait);

    free(context.encrypt_wait);
    free(context.send_wait);
    free(context.mutex);
}



void* encrypt_thread(void* _context)
{

    char indata[max_block_size];
    char outdata[max_block_size];

    int bytes_read;

    struct ProducerConsumerContext* context =
        (struct ProducerConsumerContext*)_context;

    int fd = context->fd;

    while (true) {
        bytes_read = read(fd, indata, max_block_size);

        // we don't do anything about the error?
        if(bytes_read <= 0){
            context->bytes_read = bytes_read;
            context->ready_to_write = true;
            pthread_cond_signal(context->send_wait);

            return NULL;
        }

        context->crypt->encrypt(indata, outdata, bytes_read);

        context->bytes_read = bytes_read;

        memcpy(context->data, outdata, bytes_read);

        context->ready_to_write = true;
        pthread_cond_signal(context->send_wait);

        pthread_mutex_lock(context->mutex);
        while(!context->ready_to_read)
            pthread_cond_wait(context->encrypt_wait, context->mutex);
        context->ready_to_read = false;
        pthread_mutex_unlock(context->mutex);

    }
}


void* send_thread(void* _context)
{

    struct ProducerConsumerContext* context =
        (struct ProducerConsumerContext*)_context;

    while (true) {
        char outdata[max_block_size];
        int ss;
        int ssize = 0;
        pthread_mutex_lock(context->mutex);
        while(!context->ready_to_write)
            pthread_cond_wait(context->send_wait, context->mutex);
        context->ready_to_write = false;
        pthread_mutex_unlock(context->mutex);
        int bytes_read = context->bytes_read;

        if (bytes_read <= 0) {
            pthread_cond_signal(context->encrypt_wait);
            return NULL;
        }

        memcpy(outdata, context->data, bytes_read);
        context->ready_to_read = true;
        pthread_cond_signal(context->encrypt_wait);

        while(ssize < bytes_read) {

            if (UDT::ERROR == (ss = UDT::send(*context->udt_socket,
                    outdata + ssize, bytes_read - ssize, 0)))
                return NULL;
            ssize += ss;
        }
    }
}


