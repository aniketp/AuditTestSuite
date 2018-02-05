#!/bin/sh

audit_control="/etc/security/audit_control"
audit_daemon='/etc/rc.conf'

# Array containing all network system calls to be tested
syscalls="socket(2) setsockopt(2) bind(2) listen(2)
           accept(2) sendto(2) recvfrom(2)"


# Fetches the location of Audit trails
# Default: /var/audit
auditdir=$(cat ${audit_control} | grep "dir:" | cut -d ':' -f 2)
echo "Audit Directory: ${auditdir} .. ✔"


# Inserts auditd_enable="YES" in /etc/rc.conf
# if not already done
enable_audit()
{
    sed -i "" '/auditd_enable/d' "$audit_daemon"
    echo "auditd_enable=\"YES\"" >> "$audit_daemon"
    echo "Audit daemon configured .. ✔"
    return
}


# Set flags as network(nt) audit_class
set_flag()
{
    sed -i "" '/\<flags:/s/\(.*\)/flags:lo,nt/' "$audit_control"
    echo "Set Associated flag: (nt) .. ✔"
    return
}


# Start audit daemon and catch the generated trails
start_audit()
{
    # Start audit daemon and setup a new trail
    local init="service auditd start"
    local newt="audit -n"

    eval ${init}; eval ${newt}
    echo "Audit daemon and new trail started .. ✔"
    return
}


# Stop Audit daemon
stop_audit()
{
    local stop="audit -t &> /dev/null"
    eval ${stop}
    echo "Audit daemon stopped .. ✔"
    return
}


# Execute the network binary and connect using telnet
launch_syscalls()
{
    if [ ! -f ../audit/network ]; then
        echo "Please run 'make' first .. ✘"
        stop_audit
        exit 1
    fi

    # Launch network system calls
    ./network &
    echo "launching system calls .. ✔"

    # Connect to the socket
    telnet localhost 9000 | echo "message"
    echo "Connected via client .. ✔"

    return
}

test_syscalls()
{

    local main_trail=$1

    local fullpath="${auditdir}/${main_trail}"

    # Loop through the lines of $fullpath and check success
    # and failure condition of each syscall

    for syscall in $syscalls; do
        echo "Testing ${syscall}.."

        praudit -l ${fullpath} | grep ${syscall} | while read -r find_syscall; do
            # Check for success and failure mode
            check_success=$(echo ${find_syscall} | grep "return,success")
            check_failure=$(echo ${find_syscall} | grep "return,failure")

            # Can add tests for arguments, file descriptors etc

            # Check if already tested both modes
            if [ "$pass" = 1 ] && [ "$fail" = 1 ]; then
                break
            fi

            if [ "$check_success" != "" ] && [ "$pass_once" != 1 ]; then
                echo "Success mode passed: ${syscall} .. ✔"
                pass=1; pass_once=1
            fi

            if [ "$check_failure" != "" ] && [ "$fail_once" != 1 ]; then
                echo "Failure mode passed: ${syscall} .. ✔"
                fail=1; fail_once=1
            fi

        done

        # Check if both modes passed
        if [ "$pass" = 0 ]; then
            echo "Success mode failed: ${syscall} .. ✘"
        fi

        if [ "$fail" = 0 ]; then
            echo "Failure mode failed: ${syscall} .. ✘"
        fi

        # TODO: Print statistics
    done

    return
}


cleanup()
{
    echo '\nCleaning up test trails .. ✔'
    rm -f "$auditdir/$1"
    return
}


# Main function to launch all the functions above
main()
{
    enable_audit
    set_flag
    start_audit
    launch_syscalls

    # Fetch the trail corresponding to trail catched earlier
    local current_trail=$(ls ${auditdir} | grep ".not_terminated")
    local init_name=$(echo ${current_trail} | cut -d '.' -f 1)
    stop_audit

    local main_trail=$(ls ${auditdir} | grep ${init_name})
    test_syscalls ${main_trail}
    cleanup main_trail

    return
}

main
