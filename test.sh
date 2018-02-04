#!/usr/bin/env bash

audit_control="/etc/security/audit_control"
audit_daemon='/etc/rc.conf'

# Fetches the location of Audit trails
# Default: /var/audit
fetch_auditdir()
{
    local dir=$(cat ${audit_control} | grep "dir:" | cut -d ':' -f 2)
    return dir
}


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


# Catch the currently active trail, for later use
catch_trail()
{
    local auditdir=$(fetch_auditdir)
    local current_trail=$(ls ${auditdir} | grep ".not_terminated")
    return ${current_trail}

}


# Execute the network binary and connect using telnet
launch_syscalls()
{
    if [ -f "${PWD}/network" ]; then
        echo "Please run 'make' first"
    fi

    # Launch network system calls
    if ! (./network &) &> /dev/null
    then
        echo "Failed to execute network binary"
        exit 1
    fi

    # Connect to the socket
    local client='telnet localhost 9000 | echo \"message\"'
    eval ${client}

}

test_syscalls()
{
    local auditdir=$1
}


# Main function to launch all the functions above
main()
{
    enable_audit
    set_flag
    start_audit
    trail=$(catch_trail)
    auditdir=$(fetch_auditdir)
    launch_syscalls
    stop_audit

    # Fetch the trail corresponding to trail catched earlier
    init_name=$(echo ${trail} | cut -d '.' -f 1)
    main_trail=$(ls ${auditdir} | grep ${init_name})

    test_syscalls ${main_trail}
}
