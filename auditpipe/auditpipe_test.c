/*-
 * Copyright (c) 2018 Aniket Pandey
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

#include <sys/ioctl.h>

#include <bsm/audit.h>
#include <security/audit/audit_ioctl.h>

#include <atf-c.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

static int filedesc;
static FILE *fileptr;

ATF_TC(auditpipe_get_qlen);
ATF_TC_HEAD(auditpipe_get_qlen, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
					"AUDITPIPE_GET_QLEN works properly");
}

ATF_TC_BODY(auditpipe_get_qlen, tc)
{
	int qlen = -1;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLEN, &qlen));
	ATF_REQUIRE(qlen != -1);
	close(filedesc);
}


ATF_TC(auditpipe_get_qlimit);
ATF_TC_HEAD(auditpipe_get_qlimit, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
					"AUDITPIPE_GET_QLIMIT works properly");
}

ATF_TC_BODY(auditpipe_get_qlimit, tc)
{
	int qlimit = -1;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLIMIT, &qlimit));
	ATF_REQUIRE(qlimit != -1);
	close(filedesc);
}


ATF_TC_WITH_CLEANUP(auditpipe_set_qlimit);
ATF_TC_HEAD(auditpipe_set_qlimit, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
					"AUDITPIPE_SET_QLIMIT works properly");
}

ATF_TC_BODY(auditpipe_set_qlimit, tc)
{
	int test_qlimit, curr_qlimit, recv_qlimit;

	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	/* Retrieve the current QLIMIT value and store it in a file */
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLIMIT, &curr_qlimit));
	ATF_REQUIRE((fileptr = fopen("qlimit_store", "a")) != NULL);
	ATF_REQUIRE_EQ(sizeof(curr_qlimit),
		fprintf(fileptr, "%d\n", curr_qlimit));

	/*
	 * Set QLIMIT different from the current system value to confirm
	 * proper functioning of AUDITPIPE_SET_QLIMIT ioctl.
	 */
	test_qlimit = curr_qlimit - 1;
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_SET_QLIMIT, &test_qlimit));
	/* Receive modified value and check whether QLIMIT was set correctly */
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLIMIT, &recv_qlimit));
	ATF_REQUIRE_EQ(test_qlimit, recv_qlimit);

	fclose(fileptr);
	close(filedesc);
}

ATF_TC_CLEANUP(auditpipe_set_qlimit, tc)
{
	if (atf_utils_file_exists("qlimit_store")) {
		int fd, curr_qlim;
		ATF_REQUIRE((fileptr = fopen("qlimit_store", "r")) != NULL);
		ATF_REQUIRE(fscanf(fileptr, "%d", &curr_qlim));

		ATF_REQUIRE((fd = open("/dev/auditpipe", O_RDONLY)) != -1);
		/* Set QLIMIT's value as it was prior to test-case invocation */
		ATF_REQUIRE_EQ(0, ioctl(fd, AUDITPIPE_SET_QLIMIT, &curr_qlim));

		close(fd);
		fclose(fileptr);
	}
}


ATF_TC(auditpipe_get_qlimit_min);
ATF_TC_HEAD(auditpipe_get_qlimit_min, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
				"AUDITPIPE_GET_QLIMIT_MIN works properly");
}

ATF_TC_BODY(auditpipe_get_qlimit_min, tc)
{
	int qlim_min = -1;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLIMIT_MIN, &qlim_min));
	ATF_REQUIRE(qlim_min != -1);
	close(filedesc);
}


ATF_TC(auditpipe_get_qlimit_max);
ATF_TC_HEAD(auditpipe_get_qlimit_max, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
				"AUDITPIPE_GET_QLIMIT_MAX works properly");
}

ATF_TC_BODY(auditpipe_get_qlimit_max, tc)
{
	int qlim_max = -1;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLIMIT_MAX, &qlim_max));
	ATF_REQUIRE(qlim_max != -1);
	close(filedesc);
}


ATF_TC(auditpipe_qlimit_more_than_qlimit_min);
ATF_TC_HEAD(auditpipe_qlimit_more_than_qlimit_min, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies that limit for audit records "
				"in auditpipe cannot be less than QLIMIT_MIN ");
}

ATF_TC_BODY(auditpipe_qlimit_more_than_qlimit_min, tc)
{
	int qlim_min;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLIMIT_MIN, &qlim_min));

	qlim_min -= 1;
	ATF_REQUIRE_EQ(-1, ioctl(filedesc, AUDITPIPE_SET_QLIMIT, &qlim_min));
	close(filedesc);
}


ATF_TC(auditpipe_qlimit_less_than_qlimit_max);
ATF_TC_HEAD(auditpipe_qlimit_less_than_qlimit_max, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies that limit for audit records "
				"in auditpipe cannot be more than QLIMIT_MAX ");
}

ATF_TC_BODY(auditpipe_qlimit_less_than_qlimit_max, tc)
{
	int qlim_max;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLIMIT_MAX, &qlim_max));

	qlim_max += 1;
	ATF_REQUIRE_EQ(-1, ioctl(filedesc, AUDITPIPE_SET_QLIMIT, &qlim_max));
	close(filedesc);
}


ATF_TC(auditpipe_get_maxauditdata);
ATF_TC_HEAD(auditpipe_get_maxauditdata, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
				"AUDITPIPE_GET_MAXAUDITDATA works properly");
}

ATF_TC_BODY(auditpipe_get_maxauditdata, tc)
{
	int audata = -1;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_MAXAUDITDATA, &audata));
	ATF_REQUIRE(audata != -1);
	close(filedesc);
}


ATF_TC(auditpipe_flush);
ATF_TC_HEAD(auditpipe_flush, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
					"AUDITPIPE_FLUSH works properly");
}

ATF_TC_BODY(auditpipe_flush, tc)
{
	int qlen;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_FLUSH));

	/* AUDITPIPE_FLUSH clears any outstanding record in auditpipe */
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_QLEN, &qlen));
	ATF_REQUIRE_EQ(0, qlen);
	close(filedesc);
}


ATF_TC(auditpipe_get_preselect_mode);
ATF_TC_HEAD(auditpipe_get_preselect_mode, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
				"AUDITPIPE_GET_PRESELECT_MODE works properly");
}

ATF_TC_BODY(auditpipe_get_preselect_mode, tc)
{
	int mode = -1;
	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_GET_PRESELECT_MODE, &mode));
	ATF_REQUIRE(mode != -1);
	close(filedesc);
}


ATF_TC(auditpipe_set_preselect_mode);
ATF_TC_HEAD(auditpipe_set_preselect_mode, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
				"AUDITPIPE_SET_PRESELECT_MODE works properly");
}

ATF_TC_BODY(auditpipe_set_preselect_mode, tc)
{
	int recv_mode;
	int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;

	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_SET_PRESELECT_MODE, &mode));
	ATF_REQUIRE_EQ(0, ioctl(filedesc,
		AUDITPIPE_GET_PRESELECT_MODE, &recv_mode));
	ATF_REQUIRE_EQ(mode, recv_mode);
	close(filedesc);
}


ATF_TC(auditpipe_get_preselect_flags);
ATF_TC_HEAD(auditpipe_get_preselect_flags, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
				"AUDITPIPE_GET_PRESELECT_FLAGS works properly");
}

ATF_TC_BODY(auditpipe_get_preselect_flags, tc)
{
	au_mask_t fmask = {
		.am_success	=	UINT_MAX,
		.am_failure	=	UINT_MAX
	};

	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc,
		AUDITPIPE_GET_PRESELECT_FLAGS, &fmask));

	/* Check if both success and failure bits are set by this ioctl */
	ATF_REQUIRE(fmask.am_success != UINT_MAX);
	ATF_REQUIRE(fmask.am_failure != UINT_MAX);
	close(filedesc);
}


ATF_TC(auditpipe_set_preselect_flags);
ATF_TC_HEAD(auditpipe_set_preselect_flags, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
				"AUDITPIPE_SET_PRESELECT_FLAGS works properly");
}

ATF_TC_BODY(auditpipe_set_preselect_flags, tc)
{
	int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
	au_mask_t fmask, gmask;
	bzero(&fmask, sizeof(fmask));

	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	/* Set local mode auditing to not alter the system wide audit mask */
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_SET_PRESELECT_MODE, &mode));
	ATF_REQUIRE_EQ(0, ioctl(filedesc,
		AUDITPIPE_SET_PRESELECT_FLAGS, &fmask));
	ATF_REQUIRE_EQ(0, ioctl(filedesc,
		AUDITPIPE_GET_PRESELECT_FLAGS, &gmask));

	/* Check if both success and failure bits are set by this ioctl */
	ATF_REQUIRE_EQ(fmask.am_success, gmask.am_success);
	ATF_REQUIRE_EQ(fmask.am_failure, gmask.am_failure);
	close(filedesc);
}


ATF_TC(auditpipe_get_preselect_naflags);
ATF_TC_HEAD(auditpipe_get_preselect_naflags, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
			"AUDITPIPE_GET_PRESELECT_NAFLAGS works properly");
}

ATF_TC_BODY(auditpipe_get_preselect_naflags, tc)
{
	au_mask_t fmask = {
		.am_success	=	UINT_MAX,
		.am_failure	=	UINT_MAX
	};

	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	ATF_REQUIRE_EQ(0, ioctl(filedesc,
		AUDITPIPE_GET_PRESELECT_NAFLAGS, &fmask));

	/* Check if both success and failure bits are set by this ioctl */
	ATF_REQUIRE(fmask.am_success != UINT_MAX);
	ATF_REQUIRE(fmask.am_failure != UINT_MAX);
	close(filedesc);
}


ATF_TC(auditpipe_set_preselect_naflags);
ATF_TC_HEAD(auditpipe_set_preselect_naflags, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditpipe ioctl, "
			"AUDITPIPE_SET_PRESELECT_NAFLAGS works properly");
}

ATF_TC_BODY(auditpipe_set_preselect_naflags, tc)
{
	int mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
	au_mask_t fmask, gmask;
	bzero(&fmask, sizeof(fmask));

	ATF_REQUIRE((filedesc = open("/dev/auditpipe", O_RDONLY)) != -1);
	/* Set local mode auditing to not alter the system wide audit mask */
	ATF_REQUIRE_EQ(0, ioctl(filedesc, AUDITPIPE_SET_PRESELECT_MODE, &mode));
	ATF_REQUIRE_EQ(0, ioctl(filedesc,
		AUDITPIPE_SET_PRESELECT_NAFLAGS, &fmask));
	ATF_REQUIRE_EQ(0, ioctl(filedesc,
		AUDITPIPE_GET_PRESELECT_NAFLAGS, &gmask));

	/* Check if both success and failure bits are set correctly */
	ATF_REQUIRE_EQ(fmask.am_success, gmask.am_success);
	ATF_REQUIRE_EQ(fmask.am_failure, gmask.am_failure);
	close(filedesc);
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, auditpipe_get_qlen);
	ATF_TP_ADD_TC(tp, auditpipe_get_qlimit);
	ATF_TP_ADD_TC(tp, auditpipe_set_qlimit);
	ATF_TP_ADD_TC(tp, auditpipe_get_qlimit_min);
	ATF_TP_ADD_TC(tp, auditpipe_get_qlimit_max);
	ATF_TP_ADD_TC(tp, auditpipe_qlimit_more_than_qlimit_min);
	ATF_TP_ADD_TC(tp, auditpipe_qlimit_less_than_qlimit_max);
	ATF_TP_ADD_TC(tp, auditpipe_get_maxauditdata);
	ATF_TP_ADD_TC(tp, auditpipe_flush);
	ATF_TP_ADD_TC(tp, auditpipe_get_preselect_mode);
	ATF_TP_ADD_TC(tp, auditpipe_set_preselect_mode);
	ATF_TP_ADD_TC(tp, auditpipe_get_preselect_flags);
	ATF_TP_ADD_TC(tp, auditpipe_set_preselect_flags);
	ATF_TP_ADD_TC(tp, auditpipe_get_preselect_naflags);
	ATF_TP_ADD_TC(tp, auditpipe_set_preselect_naflags);

	return (atf_no_error());
}
