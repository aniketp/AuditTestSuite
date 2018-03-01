
## Testing Status

Current scenario: All the 14 included tests for File Read (fr) event class are passing in both *Success* and *Failure* modes.

|  Num  |	Syscall	 |  Status
|:-----:|:---------:|:-----------------:
1       |open(2)	|:white_check_mark:
2       |openat(2)	|:white_check_mark:
3       |readlink(2)  |:white_check_mark:
4       |readlinkat(2)|:white_check_mark:
5       |symlink(2)	 	  |:white_check_mark:
6       |symlinkat(2)		|:white_check_mark:
7       |link(2)  |:white_check_mark:
8       |linkat(2)|:white_check_mark:
9       |mkdir(2)	 	  |:white_check_mark:
10       |mkdirat(2)		|:white_check_mark:
11       |mkfifo(2)  |:white_check_mark:
12       |mkfifoat(2)|:white_check_mark:
13       |mknod(2)  |:white_check_mark:
14       |mknodat(2)|:white_check_mark:

## Directory Structure

##### src/filesystem
* **readlink.c** : Source for triggering `readlink(2)` and `readlinkat(2)`, used for following symbolic links.

* **open.c** : Source for triggering `open(2)` and `openat(2)`. Note: `syscall(2)` is used for calling open as libc converts 'open(2)' to 'openat(2)'.

* **test** : A POSIX compliant shell script which does all the hard work. From firing off the binaries to extracting the data from active trail and analysing the audit logs. Detailed functioning of the script is described later.
