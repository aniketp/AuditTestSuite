# FreeBSD Audit TestSuite
Testsuite for Security Audit Framework In FreeBSD

## Explicit System Call Testing

The test application would trigger all Syscalls one by one, evaluating that the audit record contains all the expected parameters, e.g the arguments, valid argument types, return values etc. The testing will be done for various success and failure modes, with cross checking for appropriate error codes in case of failure mode.

## Workplan Report
* [Report1: Network System Call testing](https://gist.github.com/aniketp/4311599ab72efe73d8a3d3e1c93f3759)
* [Report2: File-read System Call testing](https://gist.github.com/aniketp/ada457f284c362da5b4ecae8929a807e)
* [Report3: atf-c(3) test program for mkdir(2)](https://gist.github.com/aniketp/498b0e39b52485d50b67736779622dd6)


## Directory Structure

```
 ├── filesystem ------------ Source files and automation tool for testing file-read (fr) syscalls
 │   ├── open.c
 │   ├── link.c
 │   ├── symlink.c
 │   ├── mkfifo.c
 │   ├── mkdir.c
 │   ├── mknod.c
 │   └── run_tests --------- [Automation Script]
 ├── sockets --------------- Source files and automation tool for testing network-socket (nt) syscalls
 │   ├── tcp_socket.c
 │   ├── udp_server.c
 │   ├── udp_client.c
 │   └── run_tests --------- [Automation Script]
 ├── setup ----------------- Script to setup the testing environment (Used Once)
 └── scripts
     └── ------------------- Helper scripts for collecting stuff from audit trails
```

##### src
* **setup** : A script to setup the environment. i.e, start the audit daemon in case it is not already running and setting up the correct flag, `flags:all` in the file `audit_control`.


### Instructions
Current set of tests include the basic network system calls for both TCP & UDP sockets and tests for filesystem syscalls (in read mode).

Clone the repository,
```bash
 $ git clone git@github.com:aniketp/AuditTestSuite.git audit
```

Setup the necessary values in configuration files
```bash
 $ cd audit
 $ ./setup
```

And execute the testing script.
```bash
 $ cd sockets (or cd filesystem)
 $ make && make run
```

### Testing Status

Current scenario: All the 50 included tests are passing in both *Success* and *Failure* modes.
