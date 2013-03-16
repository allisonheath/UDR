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

//void* run_threaded_encryption(crypto *crypt, int fd, UDTSOCKET * udt_socket)
//{
//    run_threaded_cryption(crypt, fd, udt_socket, encrypt_thread, send_thread);
//}
//
//
//void* run_threaded_decryption(crypto *crypt, int fd, UDTSOCKET * udt_socket)
//{
//    run_threaded_cryption(crypt, fd, udt_socket, recv_thread, decrypt_thread);
//}


// Spurious wakeup handle loop
void safe_wait(pthread_cond_t *cond, pthread_mutex_t *mutex, bool *predicate)
{
    pthread_mutex_lock(mutex);
    while (!*predicate)
        pthread_cond_wait(cond, mutex);
    *predicate = false;
    pthread_mutex_unlock(mutex);
}

void *read_thread(void *_context)
{
    struct read_args *context = (struct read_args*)_context;

    int num_threads = context->num_threads;

    encrypter_context *encrypters = context->encrypters;
    sender_context *sender_info = context->sender_info;

    while (true) {
        for (int i = 0; i < num_threads; i++) {

            log_print(LOG_DEBUG, "Read: preparing enc: %d \n", i);

            safe_wait(&sender_info[i].done, &sender_info[i].done_mutex,
                &sender_info[i].writable);

            encrypters[i].bytes_read = read(context->fd, encrypters[i].plain,
                max_block_size);

            log_print(LOG_DEBUG, "Bytes read: %d\n", encrypters[i].bytes_read);

            encrypters[i].ready_to_encrypt = true;
            pthread_cond_signal(&encrypters[i].encrypt_wait);

            if (encrypters[i].bytes_read <= 0) {

                *(encrypters[i].readable) = true;
                pthread_cond_signal(encrypters[i].send_wait);

                // we are done so lets cleanup
                for (int j = 0; j < num_threads; j++) {
                    if (j == i)
                        continue;

                    safe_wait(&sender_info[j].done, &sender_info[j].done_mutex,
                        &sender_info[j].writable);

                    log_print(LOG_DEBUG,
                        "cleaning up thread %d becuase thrd %d\n",
                        j, i);

                    encrypters[j].bytes_read = 0;
                    encrypters[j].ready_to_encrypt = true;
                    pthread_cond_signal(&encrypters[j].encrypt_wait);
                }
                return NULL;
            }
        }
    }
}

void *send_thread(void *_context)
{
    struct send_args *context = (struct send_args*)_context;
    sender_context *sender_info = context->sender_info;

    while (true) {

        for (int i = 0; i < context->num_threads; i++) {
            int ss;
            int ssize = 0;

            safe_wait(&sender_info[i].wait, &sender_info[i].wait_mutex,
                &sender_info[i].readable);

            int bytes_read = *sender_info[i].bytes_read;

            log_print(LOG_DEBUG, "got %d bytes in sender \n", bytes_read);

            log_print(LOG_DEBUG, "sender enc %s \n", sender_info[i].outdata);

            if (bytes_read <= 0)
                return NULL;

            while (ssize < bytes_read) {
                if (UDT::ERROR == (ss = UDT::send(*context->udt_socket,
                    sender_info[i].outdata + ssize, bytes_read - ssize, 0)))
                    return NULL;
                ssize += ss;
            }

            sender_info[i].writable = true;
            pthread_cond_signal(&sender_info[i].done);
        }
    }
}

void *encrypt_thread(void *_context)
{
    struct encrypter_context* context = (struct encrypter_context*)_context;

    while (true) {

        safe_wait(&context->encrypt_wait, &context->mutex,
            &context->ready_to_encrypt);

        if (context->bytes_read <= 0) {
            log_print(LOG_DEBUG, "going to die %d\n", context->plain);
            return NULL;
        }

        log_print(LOG_DEBUG, "encrypter bytes read %d in %d\n",
            context->bytes_read, context->plain);

        //context->crypt->encrypt(context->plain, context->encrypted,
        //    context->bytes_read);
        memcpy(context->encrypted, context->plain, context->bytes_read);

        log_print(LOG_DEBUG, "enc enc %d %s \n", context->encrypted,
            context->encrypted);

        log_print(LOG_DEBUG, "encryption completed in %d for %d\n",
            context->plain, context->encrypted);

        *(context->readable) = true;
        pthread_cond_signal(context->send_wait);
    }
}

// TODO: actually make this so there is a decryption also
//void* run_threaded_cryption(crypto *crypt, int fd, UDTSOCKET * udt_socket,
//    void *(*producer) (void *), void *(*consumer) (void *))
void* run_threaded_encryption(crypto *crypt, int fd, UDTSOCKET * udt_socket)
{
    int num_threads = num_encryption_threads;

    struct read_args read_thread_args;

    pthread_cond_init(&read_thread_args.wait, NULL);
    pthread_mutex_init(&read_thread_args.mutex, NULL);

    struct send_args send_thread_args;

    struct sender_context sender_info[num_encryption_threads];
    struct encrypter_context encrypters[num_encryption_threads];

    for (int i = 0; i < num_threads; i++) {
        pthread_cond_init(&sender_info[i].wait, NULL);
        pthread_cond_init(&sender_info[i].done, NULL);

        pthread_mutex_init(&sender_info[i].wait_mutex, NULL);
        pthread_mutex_init(&sender_info[i].done_mutex, NULL);

        // This is true because the buffer is empty and ready to be used
        sender_info[i].writable = true;

        // Set this after we have called read
        encrypters[i].ready_to_encrypt = false;

        // This needs to be set after the encrypter has filled the buffer
        sender_info[i].readable = false;

        pthread_mutex_init(&encrypters[i].mutex, NULL);
        pthread_cond_init(&encrypters[i].encrypt_wait, NULL);

        encrypters[i].crypt = crypt;

        sender_info[i].bytes_read = &encrypters[i].bytes_read;
        sender_info[i].outdata = encrypters[i].encrypted;
        encrypters[i].send_wait = &sender_info[i].wait;
        encrypters[i].readable = &sender_info[i].readable;
    }

    read_thread_args.encrypters = encrypters;

    read_thread_args.sender_info = sender_info;
    send_thread_args.sender_info = sender_info;

    read_thread_args.num_threads = num_threads;
    send_thread_args.num_threads = num_threads;

    read_thread_args.fd = fd;

    send_thread_args.udt_socket = udt_socket;

    pthread_t read;
    pthread_t send;
    pthread_t encrypt[num_encryption_threads];


    if (pthread_create(&read, NULL, read_thread, (void*)&read_thread_args)) {
        fprintf(stderr, "couldn't create producer thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&send, NULL, send_thread, (void*)&send_thread_args)) {
        fprintf(stderr, "Could not create consumer thread");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&encrypt[i], NULL, encrypt_thread,
            (void*)&encrypters[i])) {
            fprintf(stderr, "Could not create encrypter thread");
            exit(EXIT_FAILURE);
        }
    }

    pthread_join(read, NULL);
    pthread_join(send, NULL);

    for (int i = 0; i < num_threads; i++) {
        pthread_join(encrypt[i], NULL);
    }

    log_print(LOG_DEBUG, "joined all the threads");

    pthread_cond_destroy(&read_thread_args.wait);

    for (int i = 0; i < num_threads; i++) {
        pthread_cond_destroy(&sender_info[i].wait);

        pthread_cond_destroy(&sender_info[i].done);

        pthread_mutex_destroy(&sender_info[i].wait_mutex);
        pthread_mutex_destroy(&sender_info[i].done_mutex);

        pthread_mutex_destroy(&encrypters[i].mutex);
        pthread_cond_destroy(&encrypters[i].encrypt_wait);
    }

    return NULL;
}

