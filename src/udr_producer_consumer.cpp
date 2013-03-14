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
#include "udr_log.h"
#include "udr_producer_consumer.h"

void* run_threaded_cryption(crypto *crypt, int fd, UDTSOCKET * udt_socket,
    void *(*producer) (void *), void *(*consumer) (void *))
{
    struct ProducerConsumerContext context;
    context.producer_wait = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
    context.consumer_wait = (pthread_cond_t*)malloc(sizeof(pthread_cond_t));
    context.mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
    context.fd = fd;
    context.udt_socket = udt_socket;
    context.crypt = crypt;

    context.writable = context.data;
    context.readable = context.data + max_block_size;

    pthread_cond_init(context.producer_wait, NULL);
    pthread_cond_init(context.consumer_wait, NULL);
    pthread_mutex_init(context.mutex, NULL);

    pthread_t prod;
    pthread_t cons;


    if (pthread_create(&prod, NULL, producer, (void*)&context) != 0) {
        fprintf(stderr, "couldn't create producer thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&cons, NULL, consumer, (void*)&context) != 0) {
        fprintf(stderr, "Could not create consumer thread");
        pthread_join(prod, NULL);
        exit(EXIT_FAILURE);
    }

    pthread_join(prod, NULL);
    pthread_join(cons, NULL);

    pthread_mutex_destroy(context.mutex);
    pthread_cond_destroy(context.producer_wait);
    pthread_cond_destroy(context.consumer_wait);

    free(context.producer_wait);
    free(context.consumer_wait);
    free(context.mutex);
}

void buffer_swap(ProducerConsumerContext *context)
{
    char * temp = context->readable;
    context->readable = context->writable;
    context->writable = temp;
}

void* encrypt_thread(void* _context)
{
    char indata[max_block_size];

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
            pthread_cond_signal(context->consumer_wait);

            return NULL;
        }

        context->crypt->encrypt(indata, context->writable, bytes_read);

        context->bytes_read = bytes_read;

        context->ready_to_write = true;
        pthread_cond_signal(context->consumer_wait);

        pthread_mutex_lock(context->mutex);
        while(!context->ready_to_read)
            pthread_cond_wait(context->producer_wait, context->mutex);
        context->ready_to_read = false;
        pthread_mutex_unlock(context->mutex);

    }
}

void* send_thread(void* _context)
{

    struct ProducerConsumerContext* context =
        (struct ProducerConsumerContext*)_context;

    while (true) {
        int ss;
        int ssize = 0;
        pthread_mutex_lock(context->mutex);
        while(!context->ready_to_write)
            pthread_cond_wait(context->consumer_wait, context->mutex);
        context->ready_to_write = false;
        pthread_mutex_unlock(context->mutex);
        int bytes_read = context->bytes_read;

        if (bytes_read <= 0) {
            pthread_cond_signal(context->producer_wait);
            return NULL;
        }

        //memcpy(outdata, context->data, bytes_read);
        buffer_swap(context);

        context->ready_to_read = true;
        pthread_cond_signal(context->producer_wait);

        while(ssize < bytes_read) {

            if (UDT::ERROR == (ss = UDT::send(*context->udt_socket,
                    context->readable + ssize, bytes_read - ssize, 0)))
                return NULL;
            ssize += ss;
        }
    }
}

void* recv_thread(void* _context)
{
    struct ProducerConsumerContext* context =
        (struct ProducerConsumerContext*)_context;

    context->ready_to_read = false;

    while (true) {
        int bytes_read;

        if (UDT::ERROR == (bytes_read = UDT::recv(*context->udt_socket, context->writable, max_block_size, 0))) {
            context->bytes_read = bytes_read;
            context->ready_to_write = true;
            pthread_cond_signal(context->consumer_wait);

            return NULL;
        }
        context->bytes_read = bytes_read;
        log_print(LOG_DEBUG, "got %d bytes in recv_thread\n", bytes_read);

        context->ready_to_write = true;
        pthread_cond_signal(context->consumer_wait);

        pthread_mutex_lock(context->mutex);
        while(!context->ready_to_read)
            pthread_cond_wait(context->producer_wait, context->mutex);
        context->ready_to_read = false;
        pthread_mutex_unlock(context->mutex);
    }
}

void* decrypt_thread(void* _context)
{
    struct ProducerConsumerContext* context =
        (struct ProducerConsumerContext*)_context;

    context->ready_to_write = false;
    while (true) {
        char outdata[max_block_size];

        pthread_mutex_lock(context->mutex);
        while(!context->ready_to_write)
            pthread_cond_wait(context->consumer_wait, context->mutex);
        context->ready_to_write = false;
        pthread_mutex_unlock(context->mutex);
        int bytes_read = context->bytes_read;
        log_print(LOG_DEBUG, "got %d bytes in decrypt_thread\n", bytes_read);

        if (bytes_read <= 0) {
            pthread_cond_signal(context->producer_wait);
            return NULL;
        }

        buffer_swap(context);

        context->ready_to_read = true;
        pthread_cond_signal(context->producer_wait);

        context->crypt->encrypt(context->readable, outdata, bytes_read);

        int written_bytes = write(context->fd, outdata, bytes_read);
    }
}

void* run_threaded_encryption(crypto *crypt, int fd, UDTSOCKET * udt_socket)
{
    run_threaded_cryption(crypt, fd, udt_socket, encrypt_thread, send_thread);
}


void* run_threaded_decryption(crypto *crypt, int fd, UDTSOCKET * udt_socket)
{
    run_threaded_cryption(crypt, fd, udt_socket, recv_thread, decrypt_thread);
}

