# $FreeBSD$

TESTSDIR=	${TESTSBASE}/sys/security

ATF_TESTS_C=	auditon_test

TEST_METADATA+= required_user="root"
WARNS?=	6

LDFLAGS += -lbsm

.include <bsd.test.mk>
