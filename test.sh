#!/bin/sh

audit_control="/etc/security/audit_control"
audit_daemon='/etc/rc.conf'

# Array containing all network system calls to be tested
syscalls="socket(2) setsockopt(2) bind(2) listen(2)
           accept(2) sendto(2) recvfrom(2)"


# Fetches the location of Audit trails
# Default: /var/audit
auditdir=$(cat ${audit_control} | grep "dir:" | cut -d ':' -f 2)

# Catch the currently active trail, for later use
current_trail=$(ls ${auditdir} | grep ".not_terminated")


# Inserts auditd_enable="YES" in /etc/rc.conf
# if not already done
enable_audit()
{
    sed -i "" '/auditd_enable/d' "$audit_daemon"
    echo "auditd_enable=\"YES\"" >> "$audit_daemon"
    return
}


# Set flags as network(nt) audit_class
set_flag()
{
    sed -i "" '/\<flags:/s/\(.*\)/flags:nt/' "$audit_control"
    return
}


# Start audit daemon and catch the generated trails
start_audit()
{
    # Start audit daemon and setup a new trail
    local init="service auditd start"
    local newt="audit -n"

    eval ${init}; eval ${newt}
    return
}


# Stop Audit daemon
stop_audit()
{
    local stop="audit -t"
    eval ${stop}
    return
}


# Execute the network binary and connect using telnet
launch_syscalls()
{
    if [ -f "${PWD}/network" ]; then
        echo "Please run 'make' first"
    fi

    # Launch network system calls
    local launch="./network &"
    eval ${launch}
    #if [ ! $(./network &) ]
    #then
    #    echo "Failed to execute network binary"
    #    exit 1
    #fi

    # Connect to the socket
    local client='telnet localhost 9000 | echo \"message\"'
    eval ${client}

    return
}

test_syscalls()
{

    local main_trail=$1

    local fullpath="${auditdir}/${main_trail}"

    # Loop through the lines of $fullpath and check success
    # and failure condition of each syscall

    for syscall in $syscalls; do
        pass=false; fail=false
        echo "Testing ${syscall}.."

        for line in $(praudit -l ${fullpath}); do
            find_syscall=$(echo ${line} | grep "${syscall}")

            if [ "$find_syscall" != "" ]; then
                # Check for success and failure mode
                check_success=$(echo ${find_syscall} | grep "return,success")
                check_failure=$(echo ${find_syscall} | grep "return,failure")

                # Can add tests for arguments, file descriptors etc

                # Check if already tested both modes
                if [ "$pass" = true ] && [ "$fail" = true ]; then
                    break
                fi

                if [ "$check_success" != "" ]; then
                    echo "Success mode passed: ${syscall}"
                    pass=true
                fi

                if [ "$check_failure" != "" ]; then
                    echo "Failure mode passed: ${syscall}"
                    fail=true
                fi
            fi

        done

        # Check if both modes passed
        if [ "$pass" = false ]; then
            echo "Success mode failed: ${syscall}"
        fi

        if [ "$fail" = false ]; then
            echo "Failure mode failed: ${syscall}"
        fi

        # TODO: Print statistics
    done

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
    local init_name=$(echo ${current_trail} | cut -d '.' -f 1)
    local main_trail=$(ls ${auditdir} | grep ${init_name})

    stop_audit
    test_syscalls ${main_trail}
    # TODO: Implement cleanup

    return
}

main
