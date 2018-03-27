
## Testing Status

Current scenario: All the 10 included tests for TCP and UDP sockets are passing in both *Success* and *Failure* modes.

|  Num  |	Syscall	 |  Status
|:-----:|:---------:|:-----------------:
1       |socket(2)	 	|:heavy_check_mark:
2       |bind(2)		|:heavy_check_mark:
3       |setsockopt(2)  |:heavy_check_mark:
4       |listen(2)      |:heavy_check_mark:
5       |accept(2)		|:heavy_check_mark:
6       |sendto(2)		|:heavy_check_mark:
7       |recvfrom(2)	|:heavy_check_mark:
8       |shutdown(2)	| (TBD)
9       |connect(2)     |:heavy_check_mark:
10      |sendmsg(2)     |:heavy_check_mark:
11      |recvmsg(2)     |:heavy_check_mark:


## Directory Structure

##### src/sockets
* **tcp_socket.c** : Implementation of basic TCP socket which fires off a series of network syscalls. Each function is called twice, with the socket file descriptor being incorrect in one of the case, resulting in an expected error. Attempt is made to log both instances of each system call and then check whether the audit daemon logs them with the appropriate success and error message along with correct arguments.

* **udp_socket.c** : Pair of source files to launch `recvmsg(2)` and `sendmsg(2)` functions for testing UDP socket audit.

* **run\_tests** : A POSIX compliant shell script which does all the hard work. From firing off the network binaries to extracting the data from active trail and analysing the audit logs. Detailed functioning of the script is described later.
