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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>



#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>


#define USE_SOCKETS
#include "e_os.h"

#include <string>
#include <iostream>
#include <udt.h>


#include "tls_common.h"

#define BUF_SIZE (1024*8)

using std::string;
using std::cerr;
using std::endl;

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

    /*
    if (!SSL_CTX_set_cipher_list(*ctx, )) {
        ERR_print_errors(bio_err);
        return 0;
    }
    */
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

// we want to read and write to the ssl bio pair
// using udt for our purposes we can limit ourselves to one server connection
// eliminating the need to deal with openssl threading issues
int doit_biopair(SSL *s_ssl, UDTSOCKET recver, int is_server, int in_out_file)
{
    BIO *s_ssl_bio = NULL;
    BIO *server = NULL;
    BIO *server_io = NULL;

    int ret = 1;

    size_t bufsiz = BUF_SIZE;

    int line_size = 0;
    ssize_t sock_read_size = 0;
    int sock_written = 0;
    int to_send = 0;
    char line[BUF_SIZE];
    char data[BUF_SIZE]; // think about this size

    if (!BIO_new_bio_pair(&server, bufsiz, &server_io, bufsiz))
        goto err;

    s_ssl_bio = BIO_new(BIO_f_ssl());
    if (!s_ssl_bio)
        goto err;

    if (is_server)
        SSL_set_accept_state(s_ssl);
    else
        SSL_set_connect_state(s_ssl);

    SSL_set_bio(s_ssl, server, server);
    (void)BIO_set_ssl(s_ssl_bio, s_ssl, BIO_NOCLOSE);

    while (true) {
    /*  1. read from stdin. blocking
        2. write to ssl. non-blocking
        3. read from socket non-blocking
        4. write from the socket buffer to ssl
        5. read from ssl. non-blocking
        6. write to socket from the ssl buffer. blocking */
        int r;

        // for this simple echo server client pair we only want
        // to read from the client
        if (!is_server && line_size == 0) {
            //line_size = getline(&line, &bufsiz, stdin);
            line_size = read(in_out_file, line, bufsiz);
        }

        if (line_size > 0) {
            r = BIO_write(s_ssl_bio, line, line_size);
            if (r < 0) {
                if (!BIO_should_retry(s_ssl_bio)) {
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
            if (UDT::ERROR == (sock_read_size = UDT::recv(recver, data, sizeof(data), 0))) {
                if (UDT::getlasterror().getErrorCode() == 6002);
                else {
                    fprintf(stderr, "recv: %s \n",
                        UDT::getlasterror().getErrorMessage());
                    goto err;
                }
            }
        }

        if (sock_read_size > 0) {
            ssize_t num = sock_read_size;
            r = BIO_ctrl_get_write_guarantee(server_io);
            if (r < num)
                num = r;

            if (num) {
                char *dataptr;

                if (INT_MAX < num)
                    num = INT_MAX;
                if (num > 1)
                    --num; /* test restartability even more thoroughly */

                r = BIO_nwrite0(server_io, &dataptr);
                assert(r > 0);
                if (r < (int)num)
                    num = r;

                memcpy(dataptr, data + sock_written, num);

                r = BIO_nwrite(server_io, &dataptr, (int)num);
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
            char sbuf[BUF_SIZE]; // think about this size

            r = BIO_read(s_ssl_bio, sbuf, sizeof(sbuf));
            if (r < 0) {
                if (!BIO_should_retry(s_ssl_bio)) {
                    fprintf(stderr,"ERROR in SERVER\n");
                    goto err;
                }
            }
            else if (r == 0) {
                fprintf(stderr,"SSL SERVER STARTUP FAILED\n");
                goto err;
            }
            else {
                write(in_out_file, sbuf, r);
            }
        }


        // write to the socket hence the client
        do {
            size_t num;
            int r;

            to_send = num = BIO_ctrl_pending(server_io);
            // we have no clue how much we can write we just want
            // to send it and see what happens

            if (num)
            {
                char *dataptr;
                int ssize = 0;
                if (INT_MAX < num) /* yeah, right */
                    num = INT_MAX;

                r = BIO_nread(server_io, &dataptr, (int)num);
                assert(r > 0);
                assert(r <= (int)num);
                num = r;

                while (ssize < num) {
                    int ss;
                    if (UDT::ERROR == (ss = UDT::send(recver, dataptr + ssize,
                        num - ssize, 0))) {
                        fprintf(stderr, "send: %s\n", UDT::getlasterror().getErrorMessage());
                        goto err;
                    }
                    ssize += ss;
                }

                if (r != (int)num) /* can't happen */
                {
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

    if (server)
        BIO_free(server);
    if (server_io)
        BIO_free(server_io);
    if (s_ssl_bio)
        BIO_free(s_ssl_bio);

    //if (line)
    //    free(line);
    return ret;
}

int udt_server_conn(UDTSOCKET *recver)
{
    UDT::startup();

    addrinfo hints;
    addrinfo* res;

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    string service("9000");

    if (0 != getaddrinfo(NULL, service.c_str(), &hints, &res)) {
        fprintf(stderr, "illegal port number or port is busy.\n");
        return 0;
    }

    UDTSOCKET serv = UDT::socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (UDT::ERROR == UDT::bind(serv, res->ai_addr, res->ai_addrlen)) {
        fprintf(stderr, "bind: %s", UDT::getlasterror().getErrorMessage());
        return 0;
    }

    freeaddrinfo(res);

    fprintf(stderr, "server is ready at port: %s\n", service.c_str());

    if (UDT::ERROR == UDT::listen(serv, 1))
    {
       fprintf(stderr, "listen: %s\n", UDT::getlasterror().getErrorMessage());
       return 0;
    }

    sockaddr_storage clientaddr;
    int addrlen = sizeof(clientaddr);

    if (UDT::INVALID_SOCK == (*recver = UDT::accept(serv,
        (sockaddr*)&clientaddr, &addrlen))) {
        fprintf(stderr, "accept: %s\n", UDT::getlasterror().getErrorMessage());
        return 0;
    }

    UDT::close(serv);

    return 1;
}

int udt_client_conn(UDTSOCKET *recver, char *server_host, char *server_port)
{
    UDT::startup();

    struct addrinfo hints, *local, *peer;

    memset(&hints, 0, sizeof(struct addrinfo));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (0 != getaddrinfo(NULL, "9000", &hints, &local))
    {
        cerr << "incorrect network address.\n" << endl;
        return 0;
    }

    *recver = UDT::socket(local->ai_family, local->ai_socktype, local->ai_protocol);

    freeaddrinfo(local);

    if (0 != getaddrinfo(server_host, server_port, &hints, &peer))
    {
        cerr << "incorrect server/peer address. " << server_host << ":" << server_port << endl;
        return 0;
    }

    // connect to the server, implict bind
    if (UDT::ERROR == UDT::connect(*recver, peer->ai_addr, peer->ai_addrlen))
    {
        cerr << "connect: " << UDT::getlasterror().getErrorMessage() << endl;
        return 0;
    }

    bool block = false;
    UDT::setsockopt(*recver, 0, UDT_RCVSYN, &block, sizeof(bool));

    freeaddrinfo(peer);

    return 1;
}

