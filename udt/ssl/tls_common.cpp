/*****************************************************************************
Copyright 2013 Laboratory for Advanced Computing at the University of Chicago

This file is part of .

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
#define _BSD_SOURCE 1

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define USE_SOCKETS
#include "e_os.h"

#include <iostream>
#include <set>
#include <string>
#include <udt.h>

#include "tls_common.h"

//#define BUF_SIZE (1024*64*2 + 1)
#define BUF_SIZE 22368

using std::cerr;
using std::endl;
using std::string;

static void lock_dbg_cb(int mode, int type, const char *file, int line)
{
    static int modes[CRYPTO_NUM_LOCKS];
    const char *errstr = NULL;
    int rw;

    rw = mode & (CRYPTO_READ|CRYPTO_WRITE);
    if (!((rw == CRYPTO_READ) || (rw == CRYPTO_WRITE))) {
        errstr = "invalid mode";
        goto err;
    }
    if (type < 0 || type >= CRYPTO_NUM_LOCKS) {
        errstr = "type out of bounds";
        goto err;
    }
    if (mode & CRYPTO_LOCK) {
        if (modes[type]) {
            errstr = "already locked";
            goto err;
        }
        modes[type] = rw;
    }
    else if (mode & CRYPTO_UNLOCK) {
        if (!modes[type]) {
            errstr = "not locked";
            goto err;
        }
        if (modes[type] != rw) {
            errstr = (rw == CRYPTO_READ) ?
                "CRYPTO_r_unlock on write lock" : "CRYPTO_w_unlock on read lock";
        }
        modes[type] = 0;
    }
    else {
        errstr = "invalid mode";
        goto err;
    }

err:
    if (errstr) {
        fprintf(stderr, "openssl (lock_dbg_cb): %s (mode=%d, type=%d) at %s:%d\n",
            errstr, mode, type, file, line);
    }
}

// Initialize should be done for both the client and
// the server
int ctx_init(SSL_CTX **ctx)
{
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE|BIO_FP_TEXT);

    CRYPTO_set_locking_callback(lock_dbg_cb);

    if (!((getenv("OPENSSL_DEBUG_MEMORY") != NULL) &&
        (0 == strcmp(getenv("OPENSSL_  DEBUG_MEMORY"), "off")))) {
        CRYPTO_malloc_debug_init();
        CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    }
    else {
        CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
    }

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed);

    SSL_library_init();
    SSL_load_error_strings();

    *ctx = SSL_CTX_new(TLSv1_method());

    if (*ctx == NULL) {
        ERR_print_errors(bio_err);
        return 0;
    }

    SSL_CTX_set_cipher_list(*ctx, "NULL-SHA");

    return 1;
}

int verify_paths(SSL_CTX *ctx)
{
    char *ca_path = NULL;
    char *ca_file = NULL;

    if ((!SSL_CTX_load_verify_locations(ctx, ca_file, ca_path)) ||
        (!SSL_CTX_set_default_verify_paths(ctx))) {
        ERR_print_errors(bio_err);
        return 0;
    }
    return 1;
}


struct udt_epoll_args {
    //UDTSOCKET socket;
    int efd;
    int signal_fd;
};

void *epoll_signal_thread(void *my_args)
{
    struct udt_epoll_args *args = (struct udt_epoll_args*)my_args;
    std::set<UDTSOCKET> udt_read_fds;
    char sink[1];
    int ret;

    while (true) {
        ret = UDT::epoll_wait(args->efd, &udt_read_fds, NULL, -1);
        if (ret < 1 || udt_read_fds.size() < 1)
            break;
        write(args->signal_fd, "", 1);
    }
}

int udt_epoll(int udt_efd, pthread_t *signal_thread)
{
    int proxy_fd[2];
    struct udt_epoll_args *args;

    args = (struct udt_epoll_args*)malloc(sizeof(struct udt_epoll_args));

    pipe(proxy_fd);

    args->signal_fd = proxy_fd[1];
    args->efd = udt_efd;
    //args->socket = socket;

    pthread_create(signal_thread, NULL, epoll_signal_thread, (void*)args);

    fcntl(proxy_fd[0], F_SETFL, O_NONBLOCK);

    return proxy_fd[0];
}


// we want to read and write to the ssl bio pair
// using udt for our purposes we can limit ourselves to one server connection
// eliminating the need to deal with openssl threading issues
int doit_biopair(SSL *s_ssl, UDTSOCKET recver, int is_server, int in_file, int out_file)
{
    BIO *ssl_bio = NULL;

    BIO *middle_bio = NULL;
    BIO *io_bio = NULL;

    int ret = 1;

    size_t bufsiz = BUF_SIZE;

    int line_size = 0;
    ssize_t sock_read_size = 0;
    int sock_written = 0;
    int to_send = 0;
    char line[BUF_SIZE];
    char data[BUF_SIZE]; // think about this size

    int efd;
    int udt_efd;
    int actual_udt_efd;
    struct epoll_event event;
    struct epoll_event *events;
    int epoll_events;
    int signal_sink;
    char sink[1];
    int done = 0;

    pthread_t signal_thread;

    std::set<UDTSOCKET> udt_read_fds;
    std::set<int> read_fds;

    udt_read_fds.insert(recver);
    read_fds.insert(in_file);

    if (!BIO_new_bio_pair(&middle_bio, bufsiz, &io_bio, bufsiz))
        goto err;

    ssl_bio = BIO_new(BIO_f_ssl());
    if (!ssl_bio)
        goto err;

    if (is_server)
        SSL_set_accept_state(s_ssl);
    else
        SSL_set_connect_state(s_ssl);

    SSL_set_bio(s_ssl, middle_bio, middle_bio);
    (void)BIO_set_ssl(ssl_bio, s_ssl, BIO_NOCLOSE);

    fcntl(in_file, F_SETFL, O_NONBLOCK);

    if (!(udt_efd = UDT::epoll_create()))
        goto err;
    if (!(actual_udt_efd = UDT::epoll_create()))
        goto err;

    epoll_events = UDT_EPOLL_IN;

    UDT::epoll_add_usock(actual_udt_efd, recver, &epoll_events);
    UDT::epoll_add_ssock(udt_efd, in_file, &epoll_events);
    signal_sink = udt_epoll(actual_udt_efd, &signal_thread);
    UDT::epoll_add_ssock(udt_efd, signal_sink, &epoll_events);

    while (true) {

    /*  1. read from stdin. non-blocking
        2. write to ssl. non-blocking
        3. read from socket non-blocking
        4. write from the socket buffer to ssl
        5. read from ssl. non-blocking
        6. write to socket from the ssl buffer. blocking */
        int r;

        if (!done && line_size <= 0) {
            line_size = read(in_file, line, bufsiz);
            if (line_size == 0) {
                // we are done but we want to make sure all the data gets sent
                if (is_server)
                    done = 1;
                else
                    SSL_shutdown(s_ssl);
            }
            else if (line_size < 0) {
                if (errno != EAGAIN) {
                    fprintf(stderr, "Problem reading from fd\n");
                    goto err;
                }
                UDT::epoll_wait(udt_efd, &udt_read_fds, NULL, -1,  &read_fds);
                read(signal_sink, sink, 1);
            }
        }

        if (line_size > 0) {
            r = BIO_write(ssl_bio, line, line_size);
            if (r < 0) {
                if (!BIO_should_retry(ssl_bio)) {
                    fprintf(stderr,"ERROR in SERVER\n");
                    goto err;
                }
            }
            else if (r == 0) {
                fprintf(stderr,"SSL SERVER STARTUP FAILED\n");
                goto err;
            }
            else {
                line_size -= r;
            }
        }
        // read from socket This kills the cpu if we never block
        // if we aren't waiting to read from the ssl bio
        if (sock_read_size <= 0) {
            sock_written = 0;
            if (UDT::ERROR == (sock_read_size = UDT::recv(recver, data,
                sizeof(data), 0))) {
                if (UDT::getlasterror().getErrorCode() != 6002) {
                    fprintf(stderr, "recv: %s \n",
                        UDT::getlasterror().getErrorMessage());
                    goto err;
                }
            }
        }

        if (sock_read_size > 0) {
            ssize_t num = sock_read_size;
            r = BIO_ctrl_get_write_guarantee(io_bio);
            if (r < num)
                num = r;

            if (num) {
                char *dataptr;

                if (INT_MAX < num)
                    num = INT_MAX;
                //if (num > 1)
                //    --num; /* test restartability even more thoroughly */

                r = BIO_nwrite0(io_bio, &dataptr);
                assert(r > 0);
                if (r < (int)num)
                    num = r;

                // maybe not
                memcpy(dataptr, data + sock_written, num);

                r = BIO_nwrite(io_bio, &dataptr, (int)num);
                //r = BIO_nwrite(io_bio, data + sock_written, (int)num);
                if (r != (int)num) /* can't happen */
                {
                    fprintf(stderr, "ERROR: BIO_nwrite() did not accept "
                        "BIO_nwrite0() bytes");
                    goto err;
                }
                sock_read_size -= r;
                sock_written += r;
            }
        }

        {
            char sbuf[BUF_SIZE];

            r = BIO_read(ssl_bio, sbuf, sizeof(sbuf));
            if (r < 0) {
                if (!BIO_should_retry(ssl_bio)) {
                    fprintf(stderr,"ERROR in SERVER\n");
                    goto err;
                }
            }
            else if (r == 0) {
                if (!is_server)
                    goto end;
                //goto err;
                if (done)
                    SSL_shutdown(s_ssl);
            }
            else {
                write(out_file, sbuf, r);
            }
        }

        // write to the socket hence the client
        do {
            size_t num;
            int r;

            to_send = num = BIO_ctrl_pending(io_bio);

            if (num)
            {
                char *dataptr;
                int ssize = 0;
                if (INT_MAX < num) /* yeah, right */
                    num = INT_MAX;

                r = BIO_nread(io_bio, &dataptr, (int)num);
                assert((r > 0 && r <= (int)num));
                num = r;

                while (ssize < num) {
                    int ss;
                    if (UDT::ERROR == (ss = UDT::send(recver, dataptr + ssize,
                        num - ssize, 0))) {
                        fprintf(stderr, "send: %s\n",
                            UDT::getlasterror().getErrorMessage());
                        goto err;
                    }
                    ssize += ss;
                }

                if (r != (int)num) { /* can't happen */
                    fprintf(stderr, "ERROR: BIO_write could not write "
                        "BIO_ctrl_get_write_guarantee() bytes");
                    goto err;
                }
            }
        } while (to_send);
    }
end:
    ret = 0;

err:
    ERR_print_errors(bio_err);

    //pthread_cancel(signal_thread);
    UDT::epoll_release(actual_udt_efd);
    UDT::epoll_remove_usock(actual_udt_efd, recver);
    pthread_join(signal_thread, NULL);

    if (middle_bio)
        BIO_free(middle_bio);
    if (io_bio)
        BIO_free(io_bio);
    if (ssl_bio)
        BIO_free(ssl_bio);

    return ret;
}

