# $FreeBSD$

TESTSDIR=	${TESTSBASE}/sys/audit

ATF_TESTS_C=	file-create
ATF_TESTS_C+=	file-delete
ATF_TESTS_C+=	file-read

SRCS.file-create+=	utils.c
SRCS.file-delete+=	utils.c
SRCS.file-read+=	utils.c

TEST_METADATA.file-create+= timeout="30"
TEST_METADATA.file-create+= required_user="root"
TEST_METADATA.file-delete+= timeout="30"
TEST_METADATA.file-delete+= required_user="root"
TEST_METADATA.file-read+= timeout="30"
TEST_METADATA.file-read+= required_user="root"

WARNS?=	6

CFLAGS+=	-I${.CURDIR:H:H}
LDFLAGS+=	-lbsm

.include <bsd.test.mk>
