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

#ifndef TLS_COMMON_H
#define TLS_COMMON_H

#include <openssl/bio.h>

#include <udt.h>

static BIO *bio_err = NULL;
static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int doit_biopair(SSL *s_ssl, UDTSOCKET recver, int is_server, int in_file, int out_file);

int ctx_init(SSL_CTX **ctx);

int verify_paths(SSL_CTX *ctx);

#endif
