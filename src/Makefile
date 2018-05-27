# $FreeBSD$

TESTSDIR=	${TESTSBASE}/sys/audit

ATF_TESTS_C=	file-create
ATF_TESTS_C+=	file-delete
ATF_TESTS_C+=	file-read
ATF_TESTS_C+=	file-write
ATF_TESTS_C+=	file-close
ATF_TESTS_C+=	file-attribute-access
ATF_TESTS_C+=	file-attribute-modify
ATF_TESTS_C+=	exec
ATF_TESTS_C+=	ioctl
ATF_TESTS_C+=	network
ATF_TESTS_C+=	inter-process

SRCS.file-create+=	file-create.c
SRCS.file-create+=	utils.c
SRCS.file-delete+=	file-delete.c
SRCS.file-delete+=	utils.c
SRCS.file-read+=	file-read.c
SRCS.file-read+=	utils.c
SRCS.file-write+=	file-write.c
SRCS.file-write+=	utils.c
SRCS.file-close+=	file-close.c
SRCS.file-close+=	utils.c
SRCS.file-attribute-access+=	file-attribute-access.c
SRCS.file-attribute-access+=	utils.c
SRCS.file-attribute-modify+=	file-attribute-modify.c
SRCS.file-attribute-modify+=	utils.c
SRCS.exec+=	exec.c
SRCS.exec+=	utils.c
SRCS.ioctl+=	ioctl.c
SRCS.ioctl+=	utils.c
SRCS.network+=	network.c
SRCS.network+=	utils.c
SRCS.inter-process+=	inter-process.c
SRCS.inter-process+=	utils.c

TEST_METADATA.file-create+= timeout="30"
TEST_METADATA.file-create+= required_user="root"
TEST_METADATA.file-delete+= timeout="30"
TEST_METADATA.file-delete+= required_user="root"
TEST_METADATA.file-read+= timeout="30"
TEST_METADATA.file-read+= required_user="root"
TEST_METADATA.file-write+= timeout="30"
TEST_METADATA.file-write+= required_user="root"
TEST_METADATA.file-close+= timeout="30"
TEST_METADATA.file-close+= required_user="root"
TEST_METADATA.file-attribute-access+= timeout="30"
TEST_METADATA.file-attribute-access+= required_user="root"
TEST_METADATA.file-attribute-modify+= timeout="30"
TEST_METADATA.file-attribute-modify+= required_user="root"
TEST_METADATA.exec+= timeout="30"
TEST_METADATA.exec+= required_user="root"
TEST_METADATA.ioctl+= timeout="30"
TEST_METADATA.ioctl+= required_user="root"
TEST_METADATA.network+= timeout="30"
TEST_METADATA.network+= required_user="root"
TEST_METADATA.inter-process+= timeout="30"
TEST_METADATA.inter-process+= required_user="root"

WARNS?=	6

CFLAGS+=	-I${.CURDIR:H:H}
LDFLAGS+=	-lbsm

.include <bsd.test.mk>
