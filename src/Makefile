# $FreeBSD$

TESTSDIR=	${TESTSBASE}/sys/audit

ATF_TESTS_C=	file-create

SRCS.file-create=	file-create.c
SRCS.file-create+=	utils.c

TEST_METADATA.file-create+= timeout="30"
TEST_METADATA.file-create+= required_user="root"
WARNS?=	6

CFLAGS+=	-I${.CURDIR:H:H}
LDFLAGS+=	-lbsm

.include <bsd.test.mk>
