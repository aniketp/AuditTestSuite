# $FreeBSD$

CFLAGS+=        -I${.CURDIR:H:H}
LDFLAGS+=		-lbsm

TESTSDIR=       ${TESTSBASE}/sys/audit

ATF_TESTS_C+=   file-create
TEST_METADATA.file-create+= timeout="30"
WARNS?= 6

.include <bsd.test.mk>

