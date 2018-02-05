# FreeBSD Audit TestSuite
Testsuite for Security Audit Framework In FreeBSD

### Instructions
Current set of tests include the basic network socket system calls.

Clone the repository,
```bash
 $ git clone git@github.com:aniketp/AuditTestSuite.git audit
```

And execute the testing script.
```bash
 $ make
 $ ./test.sh
```

### Testing Status

Current scenario: All the 7 included tests are passing in both *Success* and *Failure* modes.

|  Num  |	Syscall	 |  Status
|:-----:|:---------:|:-----------------:
1       |socket(2)	 	|:white_check_mark:
2       |bind(2)		|:white_check_mark:
3       |setsockopt(2)  |:white_check_mark:
4       |listen(2)      |:white_check_mark:
5       |accept(2)		|:white_check_mark:
6       |sendto(2)		|:white_check_mark:
7       |recvfrom(2)	|:white_check_mark:
8       |shutdown(2)	| (TBD)
9       |connect(2)     | (TBD)
10      |sendmsg(2)     | (TBD)
11      |recvmsg(2)     | (TBD)
