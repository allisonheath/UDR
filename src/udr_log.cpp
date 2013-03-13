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


#include <syslog.h>
#include <stdarg.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <syscall.h>
#include <assert.h>

#include "udr_log.h"
#include "version.h"

static int log_maximum_verbosity;
static bool verbose;

void log_set_maximum_verbosity(int verbosity) {
    log_maximum_verbosity = verbosity;
}

void set_verbosity(bool verbosity) {
    verbosity = verbosity;
}

int verbose_print(const char *format, ...) {
    if (verbose) {
        va_list ap;
        char *formatted;
        int ret;

        va_start(ap, format);
        vasprintf(&formatted, format, ap);
        ret = fprintf(stderr, formatted);
        free(formatted);
        va_end(ap);
        return ret;
    }
    return 0;
}

int log_print(int verbosity, const char *format, ...) {
    int r = 0;
    va_list ap;
    char *formatwithtid;
    char *all_formatted;

    if (verbosity <= log_maximum_verbosity) {
        va_start(ap, format);
        asprintf(&formatwithtid, "[%s] [tid=%lu] %s", version, syscall(SYS_gettid), format);
        assert(formatwithtid);
        vasprintf(&all_formatted, formatwithtid, ap);
        /*r = sd_journal_printv(verbosity, formatwithtid, ap); */
        openlog("udr", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL7);
        syslog(verbosity, all_formatted);
        closelog();
        free(formatwithtid);
        free(all_formatted);
        va_end(ap);
    }

    return r;
}

