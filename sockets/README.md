
## Testing Status

Current scenario: All the 10 included tests for TCP and UDP sockets are passing in both *Success* and *Failure* modes.

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
9       |connect(2)     |:white_check_mark:
10      |sendmsg(2)     |:white_check_mark:
11      |recvmsg(2)     |:white_check_mark:
