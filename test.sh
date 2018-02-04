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
    auditdir=$(fetch_auditdir)
    current_trail=$(ls ${auditdir} | grep ".not_terminated")

}
