# Regression Test-Suite for Audit Framework
An implementation of regression testsuite for FreeBSD's audit subsystem. Made as a part of [GSoC'18 with FreeBSD](https://summerofcode.withgoogle.com/projects/#4507139591110656). <br/>
**For a complete overview and further updates on the project, checkout the [Project Wiki](https://wiki.freebsd.org/SummerOfCode2018Projects/RegressionTestSuiteForAuditFramework)**.

## Project Status

<p align="center"></p>
<table align="center">
	<tr>
		<th>S. No</th>
		<th>Test Suite</th>
		<th>SLOC</th>
		<th>Status</th>
	</tr>
	<tr>
		<td colspan="4" align="center"><strong>Proposed Work</strong></td>
	</tr>
	<tr align="center">
		<td>1</td>
		<td>audit(4) subsystem</td>
		<td>8785</td>
		<td><a href="https://github.com/freebsd/freebsd/tree/master/tests/sys/audit">Merged</a></td>
	</tr>
	<tr>
		<td colspan="4" align="center"><strong>Stretch Goal</strong></td>
	</tr>
	<tr align="center">
		<td>1</td>
		<td>auditipipe(4) subsystem</td>
		<td>293</td>
		<td><a href="https://github.com/freebsd/freebsd/tree/master/tests/sys/auditpipe">Merged</a></td>
	</tr>
	<tr align="center">
		<td>2</td>
		<td>praudit(1) viewer utility</td>
		<td>136</td>
		<td><a href="https://github.com/freebsd/freebsd/tree/master/usr.sbin/praudit/tests">Merged</a></td>
	</tr>
	<tr align="center">
		<td>3</td>
		<td>auditon(2) system call</td>
		<td>270</td>
		<td><a href="https://github.com/aniketp/AuditTestSuite/tree/master/security">In Progress</a></td>
	</tr>
</table>
<p></p>

## Project Overview
FreeBSD is a rapidly developing operating system with an extreme focus on advanced security & networking features. For an OS with a widespread usage and development, testing and monitoring of security regressions becomes a critical measure. FreeBSD has an audit subsystem which is responsible for monitoring a variety of security-relevant system events, such as user-logins, configuration changes, file system & network access. Although the audit framework is indispensable for security conscious organizations running FreeBSD servers, currently there is no tool to test its reliability and the intended behaviour.

## Project Description
The project aims to develop a regression test-suite, which will evaluate the audit framework for proper logging of most auditable system calls classified in TCP/IP & UDP sockets, File I/O, process control and device management, along with the semantics of audit trail's BSM/XML/text output.

BSM tokens can be obtained via I/O multiplexing on a special clonable device `/dev/auditpipe`, by configuring various preselection parameters for local mode auditing with the provided IOCTLs. Several `libbsm(3)` APIs and functions within the FreeBSD kernel can be used to analyse syscall tokens in the audit record. Finally, `kyua(1)`'s run-time engine will be used to automate regression testing of entire operating system at once, `audit(4)` included.

## Installation and Usage
For FreeBSD **12-CURRENT** users, all verified tests in the Audit Test-Suite have already been merged in Head, starting with [r334360](https://github.com/freebsd/freebsd/commit/c6edf8b386ffcad33c5814a6ad5129aa8b13179e).
These tests can be run independently since Kyua enables standalone testing, or they can be automated to run along with the entire FreeBSD TestSuite.

* To explicitely test `audit(4)` subsystem:
``` bash
 cd /usr/tests/sys/audit
 kyua test [audit_class]:[audit_event]
```

* To explicitely test `auditpipe(4)` subsystem:
``` bash
 cd /usr/tests/sys/auditpipe
 kyua test [auditpipe_test]
```

* To test the audit viewer utility `praudit(1)`:
``` bash
 cd /usr/tests/usr.sbin/praudit
 kyua test [praudit_test]
```
A general report of a test-run can be found in [TEST-RESULT](./TEST-RESULT). This is the state after [r335791](https://github.com/freebsd/freebsd/commit/0a8d0ed4e54a09aae844be71327941cf3cd401a5)

**Note**: Port `devel/kyua` needs to be present in the base system along with the `ATF` (Automated Testing Framework) libraries (which come pre-installed with 12-CURRENT). <br/>
* Install Kyua with the FreeBSD package management tool, `pkg(7)`
```bash
 pkg install kyua
```

For FreeBSD **12/11 STABLE**, installation script is under development.

## Intricacies of Event-Auditing

#### How is event auditing implemented
FreeBSD uses OpenBSM, an implementation of Sun's BSM event auditing file format and API. OpenBSM is made up of a plethora of tools including audit-viewer applications, e.g `praudit(1)` & `auditreduce(1)` as well as the `libbsm(3)` library to provide an interface to BSM audit record stream.  The `auditd(8)` daemon is responsible for managing the kernel’s `audit(4)` mechanism and also rotates the log files whenever required.

#### How to enable event auditing
FreeBSD already has userspace support for audit system. The audit daemon, `auditd(8)` can be enabled by adding the following line to `/etc/rc.conf`:
``` bash
 echo ‘auditd_enable=“YES”’ >> /etc/rc.conf
```
A safer way is to use `sysrc(8)`
``` bash
 sysrc auditd_enable=“YES”
```
Then start (and stop) the audit daemon, with a new audit trail:
``` bash
 service auditd {one}start && audit -n;
 service auditd {one}stop
```

#### Various configuration options in audit framework
``` bash
 dir=‘/etc/security’
```
Audit configuration is defined in `${dir}/audit_control`. Various event selection expressions are defined here, also found in `${dir}/audit_class`, which lets a user configure the events to be audited. For example,
* **lo** for login-logout
* **nt** for network communication
* **pc** for process control
* **ad** for administration

`${dir}/audit_user` specifies events to be audited for each system user, like login attempts. `${dir}/audit_event` contains a list of all auditable system events.

## Implementation details
The tests will span from simple permission check of the configuration files to exhaustive system call testing. The system calls in question will be categorized in TCP/UDP network sockets, process control, file & IO management.

In addition to the application program which triggers all processes, there will be a set of ATF test cases which will be created in accordance with FreeBSD Test Suite. A self-contained automation infrastructure will be developed which will enable the independent and ad-hoc testing of the audit system.

## Explicit System Call Testing
This application would consist of a set of test programs written in `atf-c(3)`, containing independent test cases for triggering similar system calls, e.g open(2) & openat(2). Each program would test a wide variety of functionalities of corresponding system calls. Testing scenarios would ensure that the audit record contains all expected parameters, e.g the arguments, valid argument types, return values etc. The testing will be done for various success and failure modes, with cross-checking for appropriate errno codes in case of failure mode.

## Test Plan and Current Approach
1. In a situation where the system does not have the audit system enabled, the tests would usually fail or skip. However, the audit daemon can be started (and stopped) by  “service auditd one{start, stop}” without modifying `/etc/rc.conf`. This eliminates the need for a setup script as described in the deprecated test plan.

2. Create separate functions for the startup and termination of the audit daemon. This step also takes into account the possibility of `auditd(8)` running beforehand. If so, the process termination is avoided to maintain the current state of the machine. The running status can be checked by “service auditd onestatus”.

3. Audit system also allows live auditing via `auditpipe(4)` for IDS and testing purpose. This enables us to open `/dev/auditpipe` and verify the proper audit of the system call in question. Usually in cases like these, `poll(2)` helps in confirming if the opened file descriptor is ready to perform I/O operations.

4. The system may not have the proper settings in `/etc/security`. This would fail the events not covered by “audit_control” configuration file. However, `auditpipe(4)` describes quite a few `ioctl(2)` requests in audit_ioctl.h for such scenarios. `getauclassnam(3)` can be used to obtain required information from the `audit_class(5)` database.

## Workplan Report
These are the three pre-SoC reports outlining the initial approach on building and automating the tests.
* [Report1: Network System Call testing](https://gist.github.com/aniketp/4311599ab72efe73d8a3d3e1c93f3759)
* [Report2: File-read System Call testing](https://gist.github.com/aniketp/ada457f284c362da5b4ecae8929a807e)
* [Report3: atf-c(3) test program for mkdir(2)](https://gist.github.com/aniketp/498b0e39b52485d50b67736779622dd6)

## References
3 Test Suites for various sections of FreeBSD kernel and base-system were developed as 3 consecutive GSoC projects.

| Year | Project | Author |
|------|---------|--------|
|2016  | [TCP-IP Test-Suite](https://github.com/shivansh/TCP-IP-Regression-TestSuite) | Shivansh Rai |
|2017  | [Smoke Test-Suite](https://github.com/shivansh/smoketestsuite) | Shivansh Rai |
|2018  | [Audit Test-Suite](https://github.com/aniketp/AuditTestSuite) | Aniket Pandey |

External repositories involved in the project apart from [freebsd source](https://github.com/freebsd/freebsd.git)
* [jmmv/kyua](https://github.com/jmmv/kyua.git)
* [openbsm/openbsm](https://github.com/openbsm/openbsm.git)

## License
This project is licensed under the BSD-2-Clause License - see the [LICENSE](./LICENSE) file for details.
