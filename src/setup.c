/*-
 * Copyright 2018 Aniket Pandey
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */


#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <atf-c.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <bsm/libbsm.h>
#include <security/audit/audit_ioctl.h>

#include "setup.h"

bool
get_records(const char *filepath, FILE *pipestream)
{
    u_char *buff;
    tokenstr_t token;
    ssize_t size = BUFFLEN;
    char membuff[size];
    char del[] = ",";
    int reclen, bytesread = 0;

    /*
     * Open a stream on 'membuff' (address to memory buffer) for storing
     * the audit records in the default mode.'reclen' is the length of the
     * available records from auditpipe which is passed to the functions
     * au_fetch_tok(3) and au_print_flags_tok(3) for further use.
     */
    FILE *memstream = fmemopen(membuff, size, "w");
    reclen = au_read_rec(pipestream, &buff);

    /*
     * Iterate through each BSM token, extracting the bits that are
     * required to start processing the token sequences.
     */
    while (bytesread < reclen) {
        if (au_fetch_tok(&token, buff + bytesread, \
             reclen - bytesread) == ERROR) {
            atf_tc_fail("Incomplete audit record");
        };

    /* Print the tokens as they are obtained, in their default form */
        au_print_flags_tok(memstream, &token, (char *)del, AU_OFLAG_NONE);
        bytesread += token.len;
    }

    free(buff); fclose(memstream);
    return atf_utils_grep_string("%s", membuff, filepath);
}

/*
 * Ensure that the auditpipe(4) does not depend on the universal
 * audit configuration at /etc/security/audit_control by setting
 * the flag mask as the corresponding audit_class of the event
 */
void
set_preselect_mode(int filedesc, au_mask_t *fmask) {
    int fmode = AUDITPIPE_PRESELECT_MODE_LOCAL;

    /* Set local preselection mode for auditing */
    if (ioctl(filedesc, AUDITPIPE_SET_PRESELECT_MODE, &fmode) < 0) {
        atf_tc_fail("Preselection mode: %s", strerror(errno));
    }

    /* Set local preselection flag corresponding to the audit_event*/
    if (ioctl(filedesc, AUDITPIPE_SET_PRESELECT_FLAGS, fmask) < 0) {
        atf_tc_fail("Preselection flag: %s", strerror(errno));
    }

    /* This removes any outstanding record on the auditpipe */
    if (ioctl(filedesc, AUDITPIPE_FLUSH) < 0) {
        atf_tc_fail("Auditpipe flush: %s", strerror(errno));
    }
}

/*
 * Check if the auditd(8) startup was properly received at the auditpipe
 */
void
check_audit_startup(struct pollfd fd[], FILE *pipestream) {
    int timeout = 2000;
    const char *auditpath = (const char *)"audit startup";

    if (poll(fd, 1, timeout) < 0) {
        atf_tc_fail("Poll: %s", strerror(errno));
    } else {
        if (fd[0].revents & POLLIN) {
            /* We now have a proof that auditd(8) started smoothly */
            ATF_REQUIRE(get_records(auditpath, pipestream));
        } else {
            /* revents is not POLLIN */
            atf_tc_fail("Auditpipe returned an unknown event "
                        "%#x", fd[0].revents);
        }
    }
}

/*
 * Loop until the auditpipe returns something, check if it is what
 * we want else repeat the procedure until ppoll(2) times out.
 */
void
check_audit(struct pollfd fd[], const char *filepath, FILE *pipestream) {
    struct timespec curptr, endptr;

    /* Set the expire time for poll(2) while waiting for mkdir(2) */
    ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &endptr));
    endptr.tv_sec += 5;

    while(true) {
        /* Update the current time left for auditpipe to return any event */
        ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &curptr));
        curptr.tv_sec = endptr.tv_sec - curptr.tv_sec;

        switch(ppoll(fd, 1, &curptr, NULL)) {
            /* ppoll(2) returns an event, check if it's the event we want */
            case 1:
                if (fd[0].revents & POLLIN) {
                    if (get_records(filepath, pipestream)) {
                    /* We have confirmed mkdir(2)' audit */
                        atf_tc_pass();
                    }
                } else {
                    atf_tc_fail("Auditpipe returned an unknown event "
                                "%#x", fd[0].revents);
                } break;

            /* poll(2) timed out */
            case 0:
                atf_tc_fail("Auditpipe did not return anything within "
                            "the time limit"); break;
            /* poll(2) standard error */
            case ERROR:
                atf_tc_fail("Poll: %s", strerror(errno)); break;

            default:
                atf_tc_fail("Poll returned an unknown event");
        }
    }

    /* Cleanup */
    fclose(pipestream);
    close(fd[0].fd);
}

/*
 * Get the corresponding audit_class for class-name "name" then set the
 * success and failure bits for fmask to be used as the ioctl argument
 */
au_mask_t
get_audit_class(const char *name) {
    au_mask_t fmask;
    au_class_ent_t *class;

    ATF_REQUIRE((class = getauclassnam(name)) != NULL);
    fmask.am_success = class->ac_class;
    fmask.am_failure = class->ac_class;
    return fmask;
}

FILE
*setup(struct pollfd fd[], const char *name) {
    au_mask_t fmask;
    fmask = get_audit_class(name);

    fd[0].fd = open("/dev/auditpipe", O_RDONLY);
    fd[0].events = POLLIN;
    FILE *pipestream = fdopen(fd[0].fd, "r");

    ATF_REQUIRE_EQ(0, system("service auditd onestatus || \
     { service auditd onestart && touch started_auditd ; }"));

    /* If 'started_auditd' exists, that means we started auditd */
    if (atf_utils_file_exists("started_auditd")) {
        check_audit_startup(fd, pipestream);
    }
    set_preselect_mode(fd[0].fd, &fmask);
    return pipestream;
}
