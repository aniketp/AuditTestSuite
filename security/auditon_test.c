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

#include <bsm/audit.h>
#include <bsm/libbsm.h>

#include <atf-c.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

static FILE *fileptr;


ATF_TC(auditon_getkaudit);
ATF_TC_HEAD(auditon_getkaudit, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditon's cmd, "
					"argument A_GETKAUDIT works properly");
}

ATF_TC_BODY(auditon_getkaudit, tc)
{
	au_tid_addr_t curr_tid_addr = {
		.at_port	=	UINT_MAX,
		.at_type	=	UINT_MAX,
		.at_addr	=	{UINT_MAX}
	};

	au_mask_t fmask = {
		.am_success	=	UINT_MAX,
		.am_failure	=	UINT_MAX
	};

	auditinfo_addr_t curr_kaudit = {
		.ai_auid	=	UINT_MAX,
		.ai_mask	=	fmask,
		.ai_termid	=	curr_tid_addr,
		.ai_asid	=	INT_MAX,
		.ai_flags	=	UINT_MAX
	};

	ATF_REQUIRE_EQ(0, auditon(A_GETKAUDIT, &curr_kaudit,
		sizeof(auditinfo_addr_t)));

	ATF_REQUIRE(curr_kaudit.ai_auid != UINT_MAX);
	ATF_REQUIRE(curr_kaudit.ai_mask.am_success != UINT_MAX);
	ATF_REQUIRE(curr_kaudit.ai_mask.am_failure != UINT_MAX);
	ATF_REQUIRE(curr_kaudit.ai_asid != INT_MAX);
	ATF_REQUIRE(curr_kaudit.ai_termid.at_port != UINT_MAX);
	ATF_REQUIRE(curr_kaudit.ai_termid.at_type != UINT_MAX);
	ATF_REQUIRE(curr_kaudit.ai_termid.at_addr[0] != UINT_MAX);
	ATF_REQUIRE(curr_kaudit.ai_flags != UINT_MAX);
}


ATF_TC_WITH_CLEANUP(auditon_setkaudit);
ATF_TC_HEAD(auditon_setkaudit, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditon's cmd, "
					"argument A_SETKAUDIT works properly");
}

ATF_TC_BODY(auditon_setkaudit, tc)
{
	au_class_ent_t *auclass;
	auditinfo_addr_t curr_kaudit, recv_kaudit;
	bzero(&curr_kaudit, sizeof(auditinfo_addr_t));
	bzero(&recv_kaudit, sizeof(auditinfo_addr_t));

	/* Retrieve the current Host status and store current the audit_mask */
	ATF_REQUIRE_EQ(0, auditon(A_GETKAUDIT, &curr_kaudit,
		sizeof(auditinfo_addr_t)));
	ATF_REQUIRE((fileptr = fopen("setkaudit_store", "a")) != NULL);
	ATF_REQUIRE(fprintf(fileptr, "%d\n",
		curr_kaudit.ai_mask.am_success) != -1);

	/* Set "lo,aa" as the audit class mask, as they are system default */
	ATF_CHECK((auclass = getauclassnam("lo")) != NULL);
	curr_kaudit.ai_mask.am_success = auclass->ac_class;
	ATF_CHECK((auclass = getauclassnam("aa")) != NULL);
	curr_kaudit.ai_mask.am_success |= auclass->ac_class;

	ATF_REQUIRE_EQ(0, auditon(A_SETKAUDIT, &curr_kaudit,
		sizeof(auditinfo_addr_t)));
	/* Receive modified value and check if Host state was set correctly */
	ATF_REQUIRE_EQ(0, auditon(A_GETKAUDIT, &recv_kaudit,
		sizeof(auditinfo_addr_t)));
	ATF_REQUIRE_EQ(curr_kaudit.ai_mask.am_success,
		recv_kaudit.ai_mask.am_success);
	fclose(fileptr);
}

ATF_TC_CLEANUP(auditon_setkaudit, tc)
{
	if (atf_utils_file_exists("setkaudit_store")) {
		int success_bit;
		auditinfo_addr_t curr_kaudit;
		ATF_REQUIRE_EQ(0, auditon(A_GETKAUDIT, &curr_kaudit,
			sizeof(auditinfo_addr_t)));

		ATF_REQUIRE((fileptr = fopen("setkaudit_store", "r")) != NULL);
		ATF_REQUIRE(fscanf(fileptr, "%d", &success_bit) != -1);

		curr_kaudit.ai_mask.am_success = success_bit;
		/* Set Host state as it was prior to test-case invocation */
		ATF_REQUIRE_EQ(0, auditon(A_SETKAUDIT, &curr_kaudit,
			sizeof(auditinfo_addr_t)));
		fclose(fileptr);
	}
}


ATF_TC(auditon_getpolicy);
ATF_TC_HEAD(auditon_getpolicy, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditon's cmd, "
					"argument A_GETPOLICY works properly");
}

ATF_TC_BODY(auditon_getpolicy, tc)
{
	int curr_poll = -1;
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &curr_poll, sizeof(int)));
	ATF_REQUIRE(curr_poll != -1);
}


ATF_TC_WITH_CLEANUP(auditon_setpolicy);
ATF_TC_HEAD(auditon_setpolicy, tc)
{
	atf_tc_set_md_var(tc, "descr", "Verifies whether the auditon's cmd, "
					"argument A_SETPOLICY works properly");
}

ATF_TC_BODY(auditon_setpolicy, tc)
{
	int curr_poll, recv_poll, test_poll;

	/* Retrieve the current POLICY value and store it in a file */
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &curr_poll, sizeof(int)));
	ATF_REQUIRE((fileptr = fopen("setpolicy_store", "a")) != NULL);
	ATF_REQUIRE(fprintf(fileptr, "%d\n", curr_poll) != -1);

	/*
	 * Set policy different from the current system value to confirm
	 * proper functioning of A_SETPOLICY cmd argument.
	 */
	test_poll = AUDIT_ARGV | AUDIT_ARGE;
	ATF_REQUIRE_EQ(0, auditon(A_SETPOLICY, &test_poll, sizeof(int)));
	/* Receive modified value and check whether POLICY was set correctly */
	ATF_REQUIRE_EQ(0, auditon(A_GETPOLICY, &recv_poll, sizeof(int)));
	ATF_REQUIRE_EQ(test_poll, recv_poll);
	fclose(fileptr);
}

ATF_TC_CLEANUP(auditon_setpolicy, tc)
{
	if (atf_utils_file_exists("setpolicy_store")) {
		int cur_poll;
		ATF_REQUIRE((fileptr = fopen("setpolicy_store", "r")) != NULL);
		ATF_REQUIRE(fscanf(fileptr, "%d", &cur_poll) != -1);

		/* Set POLICY value as it was prior to test-case invocation */
		ATF_REQUIRE_EQ(0, auditon(A_SETPOLICY, &cur_poll, sizeof(int)));
		fclose(fileptr);
	}
}


ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, auditon_getkaudit);
	ATF_TP_ADD_TC(tp, auditon_setkaudit);
	ATF_TP_ADD_TC(tp, auditon_getpolicy);
	ATF_TP_ADD_TC(tp, auditon_setpolicy);

	return (atf_no_error());
}
