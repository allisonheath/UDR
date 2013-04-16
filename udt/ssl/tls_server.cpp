/*****************************************************************************
Copyright 2013 Laboratory for Advanced Computing at the University of Chicago

This file is part of TLS over UDT POC

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
/* Or gethostname won't be declared properly on Linux and GNU platforms. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define USE_SOCKETS
#include "e_os.h"

#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#include <openssl/bn.h>

#define _XOPEN_SOURCE_EXTENDED  1 /* Or gethostname won't be declared properly
                     on Compaq platforms (at least with DEC C).
                     Do not try to put it earlier, or IPv6 includes
                     get screwed...
                  */
#include OPENSSL_UNISTD

#include <udt.h>

#include "tls_common.h"

#define TEST_SERVER_CERT "server.pem"


int main(int argc, char *argv[])
{
    int ret = 1;

    char server_cert[] = TEST_SERVER_CERT;
    char *server_key = NULL;

    SSL_CTX *s_ctx = NULL;
    SSL *s_ssl;

    if (!ctx_init(&s_ctx))
        goto end;

    if (!SSL_CTX_use_certificate_file(s_ctx, server_cert, SSL_FILETYPE_PEM)) {
        ERR_print_errors(bio_err);
    }
    else if (!SSL_CTX_use_PrivateKey_file(s_ctx,
        (server_key ? server_key : server_cert), SSL_FILETYPE_PEM)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    verify_paths(s_ctx);

    {
        int session_id_context = 0;
        SSL_CTX_set_session_id_context(s_ctx,
            (const unsigned char *)(void *)&session_id_context,
            sizeof session_id_context);
    }

    s_ssl=SSL_new(s_ctx);

    UDTSOCKET recver;

    if (!udt_server_conn(&recver))
        goto end;

    ret=doit_biopair(s_ssl, recver, 1, fileno(stdout));

end:
    if (s_ctx != NULL) SSL_CTX_free(s_ctx);

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    EVP_cleanup();
    CRYPTO_mem_leaks(bio_err);
    if (bio_err != NULL) BIO_free(bio_err);

    if (recver)
        UDT::close(recver);
    UDT::cleanup();

    EXIT(ret);
    return ret;
}

