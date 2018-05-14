# $FreeBSD$

TESTSDIR=	${TESTSBASE}/sys/audit

ATF_TESTS_C=	file-create
ATF_TESTS_C+=	file-delete
ATF_TESTS_C+=	file-read
ATF_TESTS_C+=	file-write
ATF_TESTS_C+=	file-attribute-access
ATF_TESTS_C+=	file-attribute-modify

SRCS.file-create+=	file-create.c
SRCS.file-create+=	utils.c
SRCS.file-delete+=	file-delete.c
SRCS.file-delete+=	utils.c
SRCS.file-read+=	file-read.c
SRCS.file-read+=	utils.c
SRCS.file-write+=	file-write.c
SRCS.file-write+=	utils.c
SRCS.file-attribute-access+=	file-attribute-access.c
SRCS.file-attribute-access+=	utils.c
SRCS.file-attribute-modify+=	file-attribute-modify.c
SRCS.file-attribute-modify+=	utils.c

TEST_METADATA.file-create+= timeout="30"
TEST_METADATA.file-create+= required_user="root"
TEST_METADATA.file-delete+= timeout="30"
TEST_METADATA.file-delete+= required_user="root"
TEST_METADATA.file-read+= timeout="30"
TEST_METADATA.file-read+= required_user="root"
TEST_METADATA.file-write+= timeout="30"
TEST_METADATA.file-write+= required_user="root"
TEST_METADATA.file-attribute-access+= timeout="30"
TEST_METADATA.file-attribute-access+= required_user="root"
TEST_METADATA.file-attribute-modify+= timeout="30"
TEST_METADATA.file-attribute-modify+= required_user="root"

WARNS?=	6

CFLAGS+=	-I${.CURDIR:H:H}
LDFLAGS+=	-lbsm

.include <bsd.test.mk>
