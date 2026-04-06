#!/bin/bash
#
# Configure hardened Kubernetes node golden image

# Set non-interactive frontend to prevent apt hangs
export DEBIAN_FRONTEND=noninteractive

# Disable filesystem drivers for unused filesystems, which decreases the attack surface
restrict_unused_filesystems() {
  local filesystem_blacklist_file="/etc/modprobe.d/fs-blacklist.conf"
  local filesystems_to_block=(ceph cifs cramfs exfat ext firewire-core \
  freevxfs fscache fuse gfs2 hfs hfsplus jffs2 nfs_common nfsd smbfs_common \
  squashfs udf usb_storage)

  for fs in "${filesystems_to_block[@]}"; do
    {
      echo "blacklist $fs"
      echo "install $fs /bin/false"
    } >> "$filesystem_blacklist_file"
  done
}

# Mount /tmp and /dev/shm as hardened temporary filesystem
harden_tmpfs() {
  {
    # Mount /tmp as hardened tmpfs
    echo "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,mode=1777 0 0"
    # Mount /dev/shm as hardened tmpfs
    echo "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,size=1024M,mode=1777 0 0"
  } >> "/etc/fstab"
}

# Set kernel parameters to harden the kernel
harden_kernel_params() {
  local kernel_params_file="/etc/sysctl.d/kernel-hardening.conf"
  {
    echo "kernel.kptr_restrict = 2"
    echo "kernel.dmesg_restrict = 1"
    echo "dev.tty.ldisc_autoload = 0"
    echo "fs.protected_fifos = 2"
    echo "fs.protected_regular = 2"
    echo "fs.protected_hardlinks = 1"
    echo "fs.protected_symlinks = 1"
    echo "fs.suid_dumpable = 0"
    echo "kernel.core_uses_pid = 1"
    echo "kernel.core_pattern = |/bin/false"
    echo "kernel.perf_event_paranoid = 3"
    echo "kernel.randomize_va_space = 2"
    echo "kernel.unprivileged_bpf_disabled = 1"
    echo "kernel.yama.ptrace_scope = 2"
    echo "kernel.kexec_load_disabled = 1"
    echo "kernel.sysrq = 0"
    echo "net.core.bpf_jit_harden = 2"
  } >> "$kernel_params_file"
}

# Disable uncommon protocols and kernal modules as these may have unknown vulnerabilties
restrict_uncommon_network_protocols() {
  local network_protocols_blacklist_file="/etc/modprobe.d/blacklist-uncommon-networking.conf"
  local network_protocols_to_block=(atm can dccp rds sctp tipc)

  for network_protocol in "${network_protocols_to_block[@]}"; do
    {
      echo "blacklist $network_protocol"
      echo "install $network_protocol /bin/false"
    } >> "$network_protocols_blacklist_file"
  done
}

# Harden kernel parameters for IPv4
harden_ipv4_kernel_params() {
  local ipv4_kernel_params_file="/etc/sysctl.d/ipv4-hardening.conf"
  {
    echo "net.ipv4.conf.all.log_martians = 1"
    echo "net.ipv4.conf.default.log_martians = 1"
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    echo "net.ipv4.icmp_ignore_bogus_error_responses = 1"
    echo "net.ipv4.tcp_syncookies = 1"
  } >> "$ipv4_kernel_params_file"
}

# Harden core dumps & Crash logs
harden_crash_dumps_info() {
  local crash_dumps_config_file="/etc/security/limits.conf"
  {
    echo "* hard core 0"
    echo "* soft core 0"
  } >> "$crash_dumps_config_file"
}

# Connection warning about unauthorized access
connection_warning() {
  for item in /etc/issue /etc/issue.net /etc/motd; do
    {
      echo "UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED"
      echo "  You must have explicit, authorized permission to access or configure this device."
      echo "  Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties."
      echo "  All activities performed on this device are logged and monitored."
    } > "$item"
  done
}

# Harden APT and apt-related utilities and install packages
apt_configuration() {
  # Ensure apt uses the debian keyring
  sed -i 's|^deb |deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] |' /etc/apt/sources.list
  sed -i 's|^deb-src |deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] |' /etc/apt/sources.list

  # Ensure downloading packages uses https
  sed -i 's/http/https/g' /etc/apt/sources.list

  # Ensure weak dependencies are not downloaded and installed
  {
    echo 'APT::Install-Recommends "0";'
    echo 'APT::Install-Suggests "0";'
  } > /etc/apt/apt.conf.d/60-no-weak-dependencies

  # Install required packages
  apt update
  # shellcheck disable=SC2086
  apt install -y -qq $APT_PACKAGES
}

# Harden permissions for folder permissions related to users & groups
harden_user_group_folder_permissions() {
  chown root:root /etc/gshadow
  chmod 0000 /etc/gshadow

  chown root:root /etc/shadow
  chmod 0640 /etc/shadow

  chown root:root /etc/group

  chown root:root /etc/passwd
  chmod 0644 /etc/passwd
}

# Harden & log sudo usage
sudo_hardening() {
  # Harden sudo config folder access
  chmod 750 /etc/sudoers.d
  # Disable su access (sudo logging is more verbose)
  groupadd sugroup
  echo "auth required pam_wheel.so use_uid group=sugroup" > /etc/pam.d/su
  # Log sudo command access
  echo 'Defaults	logfile="/var/log/sudo.log"' > /etc/sudoers.d/01_sudo_hardening
  chmod o-r,g-r /etc/sudoers.d/01_sudo_hardening
}

# Harden & fix login and sessions
harden_login_session_options() {
  # Harden login options
  echo 'session optional pam_umask.so' >> /etc/pam.d/common-session
  {
    echo "UMASK 027"
    echo "UID_MIN 1000"
  } >> /etc/login.defs

  # Set terminal timeout
  printf 'TMOUT=300\n' >> /home/user/.bashrc
  printf 'TMOUT=300\n' >> /root/.bashrc

  # Allow root to login only from physical terminals
  for i in {1..6}; do
    echo "tty$i" >> /etc/securetty
  done

  # Fix sbin folders in PATH
  echo "export PATH=$PATH:/sbin:/usr/sbin" >> /root/.bashrc
}

# Harden ssh and ssh configuration, and harden ssh related files and folders
harden_ssh() {
  # SSHD hardening options
  {
    echo "# Cryptography"
    echo "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    echo "KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256"
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"
    echo
    echo "# Authentication & Access Control"
    echo "AllowUsers user"
    echo "PermitRootLogin no"
    echo "PasswordAuthentication no"
    echo "PubkeyAuthentication yes"
    echo "PermitEmptyPasswords no"
    echo "MaxAuthTries 3"
    echo "LoginGraceTime 60"
    echo "HostbasedAuthentication no"
    echo "IgnoreRhosts yes"
    echo
    echo "# Session & Connection Management"
    echo "MaxSessions 2"
    echo "MaxStartups 10:30:60"
    echo "TCPKeepAlive no"
    echo "ClientAliveInterval 150"
    echo "ClientAliveCountMax 2"
    echo "Compression no"
    echo
    echo "# Restriction & Forwarding"
    echo "DisableForwarding yes"
    echo "AllowAgentForwarding no"
    echo "AllowTcpForwarding no"
    echo "X11Forwarding no"
    echo "PermitUserEnvironment no"
    echo
    echo "# Logging & UI"
    echo "Banner /etc/issue"
    echo "LogLevel VERBOSE"
  } > /etc/ssh/sshd_config.d/hardening.conf

  # Setup SSH key authentication
  mkdir -p /home/user/.ssh
  touch /home/user/.ssh/authorized_keys

  # SSH folder permissions
  chmod 600 /etc/ssh/sshd_config
  chmod -R 600 /etc/ssh/sshd_config.d
  chown -R user:user /home/user/.ssh
  chmod 700 /home/user/.ssh
  chmod 600 /home/user/.ssh/authorized_keys
}

# Hardens cron files & folders permissions
harden_cron() {
  local cron_chown=(tab .d .hourly .daily .weekly .monthly .yearly .allow)
  local cron_600=(tab .allow)
  local cron_700=(.d .hourly .daily .weekly .monthly .yearly)

  # Allow only root to use cron
  echo root > /etc/cron.allow

  # Set owner
  for extension in "${cron_chown[@]}"; do
    chown root:root "/etc/cron$extension"
  done

  # Set rw for owner only
  for extension in "${cron_600[@]}"; do
    chmod 600 "/etc/cron$extension"
  done

  # Set rwx for owner only
  for extension in "${cron_700[@]}"; do
    chmod 700 "/etc/cron$extension"
  done
}

# Set jorunald log rotation
harden_journald() {
  mkdir -p /etc/systemd/journald.conf.d

  {
    echo "Compress=yes"
    echo "ForwardToSyslog=no"
    echo "MaxFileSec=1month"
    echo "RuntimeKeepFree=50M"
    echo "RuntimeMaxUse=200M"
    echo "Storage=persistent"
    echo "SystemKeepFree=500M"
    echo "SystemMaxUse=1G"
  } > /etc/systemd/journald.conf.d/log-rotation.conf

  sed -i 's/ForwardToSyslog=yes/ForwardToSyslog=no/g' /usr/lib/systemd/journald.conf.d/syslog.conf
}

# Haveged to improve entropy
haveged() {
  systemctl enable haveged
  printf '/usr/local/sbin/haveged -w 1024' > /etc/rc.local
}

# Configure auditd to monitor important system events
auditd() {
  # Configuration
  {
    echo "#"
    echo "# This file controls the configuration of the audit daemon"
    echo "#"
    echo
    echo "local_events = yes"
    echo "write_logs = yes"
    echo "log_file = /var/log/audit/audit.log"
    echo "log_group = adm"
    echo "log_format = ENRICHED"
    echo "flush = INCREMENTAL_ASYNC"
    echo "freq = 50"
    echo "max_log_file = 5"
    echo "num_logs = 5"
    echo "priority_boost = 4"
    echo "name_format = NONE"
    echo "##name = mydomain"
    echo "max_log_file = 5"
    echo "space_left = 75"
    echo "space_left_action = rotate"
    echo "verify_email = yes"
    echo "action_mail_acct = root"
    echo "admin_space_left = 50"
    echo "admin_space_left_action = rotate"
    echo "disk_full_action = rotate"
    echo "disk_error_action = syslog"
    echo "use_libwrap = yes"
    echo "##tcp_listen_port = 60"
    echo "tcp_listen_queue = 5"
    echo "tcp_max_per_addr = 1"
    echo "##tcp_client_ports = 1024-65535"
    echo "tcp_client_max_idle = 0"
    echo "transport = TCP"
    echo "krb5_principal = auditd"
    echo "##krb5_key_file = /etc/audit/audit.key"
    echo "distribute_network = no"
    echo "q_depth = 2000"
    echo "overflow_action = SYSLOG"
    echo "max_restarts = 10"
    echo "plugin_dir = /etc/audit/plugins.d"
    echo "end_of_event_timeout = 2"
  } > /etc/audit/auditd.conf

  # Rules
  echo "-c" >> /etc/audit/rules.d/01-initialize.rules
  {
    echo "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
    echo "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access"
    echo "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
    echo "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
  }  > /etc/audit/rules.d/50-access.rules
  {
    echo "-a always,exit -F arch=b32 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete"
    echo "-a always,exit -F arch=b64 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete"
    echo "-a always,exit -F arch=b32 -S rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k delete"
    echo "-a always,exit -F arch=b64 -S rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k delete"
  } > /etc/audit/rules.d/50-delete.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/hosts -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/hosts -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/hostname -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/hostname -F perm=wa -k system-locale"
  } > /etc/audit/rules.d/50-etc_host_system_locale.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/issue -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/issue -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/issue.net -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/issue.net -F perm=wa -k system-locale"
  } > /etc/audit/rules.d/50-etc_issue_system_locale.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/network/interfaces -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/network/interfaces -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b32 -S all -F dir=/etc/network/interfaces.d -F perm=wa -k system-locale"
    echo "-a always,exit -F arch=b64 -S all -F dir=/etc/network/interfaces.d -F perm=wa -k system-locale"
  } > /etc/audit/rules.d/50-etc_sysconfig_system_locale.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/group -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/group -F perm=wa -k identity"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/passwd -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k identity"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/gshadow -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/gshadow -F perm=wa -k identity"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/shadow -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k identity"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/security/opasswd -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/security/opasswd -F perm=wa -k identity"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/nsswitch.conf -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/nsswitch.conf -F perm=wa -k identity"
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/pam.conf -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/pam.conf -F perm=wa -k identity"
    echo "-a always,exit -F arch=b32 -S all -F dir=/etc/pam.d -F perm=wa -k identity"
    echo "-a always,exit -F arch=b64 -S all -F dir=/etc/pam.d -F perm=wa -k identity"
  } > /etc/audit/rules.d/50-identity.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b64 -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b32 -S query_module -F auid>=1000 -F auid!=unset -k kernel_modules"
    echo "-a always,exit -F arch=b64 -S query_module -F auid>=1000 -F auid!=unset -k kernel_modules"
  } > /etc/audit/rules.d/50-kernel_modules.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/localtime -F perm=wa -k localtime-change"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/localtime -F perm=wa -k localtime-change"
  }  > /etc/audit/rules.d/50-local-time-change.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/var/log/lastlog -F perm=wa -k logins"
    echo "-a always,exit -F arch=b64 -S all -F path=/var/log/lastlog -F perm=wa -k logins"
    echo "-a always,exit -F arch=b32 -S all -F path=/var/run/faillock -F perm=wa -k logins"
    echo "-a always,exit -F arch=b64 -S all -F path=/var/run/faillock -F perm=wa -k logins"
  } > /etc/audit/rules.d/50-login.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/apparmor -F perm=wa -k MAC-policy"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/apparmor -F perm=wa -k MAC-policy"
    echo "-a always,exit -F arch=b32 -S all -F dir=/etc/apparmor.d -F perm=wa -k MAC-policy"
    echo "-a always,exit -F arch=b64 -S all -F dir=/etc/apparmor.d -F perm=wa -k MAC-policy"
  } > /etc/audit/rules.d/50-MAC-policy.rules
  {
    echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"
    echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts"
  } > /etc/audit/rules.d/50-mounts.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
    echo "-a always,exit -F arch=b64 -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
    echo "-a always,exit -F arch=b32 -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
    echo "-a always,exit -F arch=b64 -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
    echo "-a always,exit -F arch=b32 -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
    echo "-a always,exit -F arch=b64 -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
  } > /etc/audit/rules.d/50-perm_chng.rules
  {
    echo "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
  } > /etc/audit/rules.d/50-perm_mod.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/etc/sudoers -F perm=wa -k scope"
    echo "-a always,exit -F arch=b64 -S all -F path=/etc/sudoers -F perm=wa -k scope"
    echo "-a always,exit -F arch=b32 -S all -F dir=/etc/sudoers.d -F perm=wa -k scope"
    echo "-a always,exit -F arch=b64 -S all -F dir=/etc/sudoers.d -F perm=wa -k scope"
  } > /etc/audit/rules.d/50-scope.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/var/run/utmp -F perm=wa -k session"
    echo "-a always,exit -F arch=b64 -S all -F path=/var/run/utmp -F perm=wa -k session"
    echo "-a always,exit -F arch=b32 -S all -F path=/var/log/wtmp -F perm=wa -k session"
    echo "-a always,exit -F arch=b64 -S all -F path=/var/log/wtmp -F perm=wa -k session"
    echo "-a always,exit -F arch=b32 -S all -F path=/var/log/btmp -F perm=wa -k session"
    echo "-a always,exit -F arch=b64 -S all -F path=/var/log/btmp -F perm=wa -k session"
  } > /etc/audit/rules.d/50-session.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/var/log/sudo.log -F perm=wa -k sudo_log_file"
    echo "-a always,exit -F arch=b64 -S all -F path=/var/log/sudo.log -F perm=wa -k sudo_log_file"
  }  > /etc/audit/rules.d/50-sudo.rules
  {
    echo "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
    echo "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
  } > /etc/audit/rules.d/50-system_locale.rules
  {
    echo "-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change"
    echo "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change"
    echo "-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change"
    echo "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change"
  } > /etc/audit/rules.d/50-time-change.rules
  {
    echo "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
    echo "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
  } > /etc/audit/rules.d/50-user_emulation.rules
  {
    echo "-a always,exit -F arch=b32 -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod"
    echo "-a always,exit -F arch=b64 -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod"
  } > /etc/audit/rules.d/50-usermod.rules
  echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules
  augenrules --load
}

# Upgrade important packages without manual intervention
unattended_upgrades() {
  {
    echo 'APT::Periodic::AutocleanInterval "7";'
    echo 'APT::Periodic::Update-Package-Lists "1";'
    echo 'APT::Periodic::Unattended-Upgrade "1";'
  } > /etc/apt/apt.conf.d/20auto-upgrades

  {
    echo 'Unattended-Upgrade::Origins-Pattern {'
    # shellcheck disable=SC2016
    echo '    "origin=Debian,codename=${distro_codename},label=Debian";'
    # shellcheck disable=SC2016
    echo '    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";'
    # shellcheck disable=SC2016
    echo '    "origin=Debian,codename=${distro_codename},label=Debian-Security";'
    echo '};'
    echo 'Unattended-Upgrade::Remove-Unused-Dependencies "true";'
    echo 'Unattended-Upgrade::Automatic-Reboot "false";'
  } > /etc/apt/apt.conf.d/50unattended-upgrades

  systemctl enable unattended-upgrades
}

# Setup and configure cloud-init
cloud_init() {
  {
    echo "users:"
    echo "  - default"
    echo
    echo "# We don't allow root ssh access in the ssh config"
    echo "disable_root: false"
    echo "# Disable key generation"
    echo "ssh_genkeytypes: []"
    echo "ssh_quiet_keygen: true"
    echo
    echo "# This will cause the set+update hostname module to not operate (if true)"
    echo "preserve_hostname: false"
    echo
    echo "apt:"
    echo "  # We already set the apt configuration"
    echo "  preserve_sources_list: true"
    echo
    echo "# The modules that run in the 'init' stage"
    echo "cloud_init_modules:"
    echo "  - set_hostname"
    echo "  - update_hostname"
    echo "  - update_etc_hosts"
    echo "  - ca-certs"
    echo "  - users-groups"
    echo "  - ssh"
    echo
    echo "# The modules that run in the 'config' stage"
    echo "cloud_config_modules:"
    echo "  - set-passwords"
    echo "  - runcmd"
    echo
    echo "# The modules that run in the 'final' stage"
    echo "cloud_final_modules:"
    echo "  - ssh"
    echo "  - scripts_user"
    echo "  - final_message"
    echo
    echo "# System and/or distro specific settings"
    echo "# (not accessible to handlers/transforms)"
    echo "system_info:"
    echo "  # This will affect which distro class gets used"
    echo "  distro: debian"
    echo "  # Other config here will be given to the distro class and/or path classes"
    echo "  paths:"
    echo "    cloud_dir: /var/lib/cloud/"
    echo "    templates_dir: /etc/cloud/templates/"
    echo "  ssh_svcname: ssh"
  } > /etc/cloud/cloud.cfg
  echo "datasource_list: [ NoCloud, ConfigDrive ]" > /etc/cloud/cloud.cfg.d/99_proxmox.cfg

  # Wipe interface ip assignment for cloud-init to assign later
  {
    echo "source /etc/network/interfaces.d/*"
    echo
    echo "# The loopback network interface"
    echo "auto lo"
    echo "iface lo inet loopback"
    echo
  } > /etc/network/interfaces

  # Wipe the machine's "identity" so it regenerates on clone
  cloud-init clean --logs --seed --machine-id
}

# Install the cosign package in order to verify file signatures
setup_cosign() {
  local COSIGN_VERSION=3.0.5

  # Download
  curl -fsSL -O "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/{cosign-linux-amd64,cosign-linux-amd64.sigstore.json,cosign_checksums.txt}"

  # Verify sha256
  if ! grep -w cosign-linux-amd64 cosign_checksums.txt | sha256sum --check; then
    echo "Sha256sum of cosign-linux-amd64 is incorrect!"
    exit 1
  fi

  # Install
  mv cosign-linux-amd64 /usr/bin/cosign
  chmod +x /usr/bin/cosign

  # Verify signature
  if ! cosign verify-blob /usr/bin/cosign \
      --bundle cosign-linux-amd64.sigstore.json \
      --certificate-identity keyless@projectsigstore.iam.gserviceaccount.com \
      --certificate-oidc-issuer https://accounts.google.com; then
    echo "Couldn't verify the file signature of cosign"
    exit 1
  fi

  # cleanup
  rm cosign*
}

# Set sysctl networking options for kubernetes
kubernetes_sysctl_networking() {
  {
    echo "net.ipv4.ip_forward = 1"
    echo "net.ipv6.conf.all.forwarding=1"
    echo "net.bridge.bridge-nf-call-ip6tables = 1"
    echo "net.bridge.bridge-nf-call-iptables = 1"
  } > /etc/sysctl.d/k8s.conf
}

# Install Kubernetes container runtime interface
install_cri() {
  local CONTAINERD_VERSION="2.2.1"
  local NERDCTL_VERSION="2.2.1"
  local RUNC_VERSION="1.4.0"
  local CNI_PLUGIN_VERSION="1.9.0"

  # Containerd
  ## Download
  curl -fsSL -O "https://github.com/containerd/containerd/releases/download/v$CONTAINERD_VERSION/containerd-$CONTAINERD_VERSION-linux-amd64.tar.gz"
  curl -fsSL "https://github.com/containerd/containerd/releases/download/v$CONTAINERD_VERSION/containerd-$CONTAINERD_VERSION-linux-amd64.tar.gz.sha256sum" \
          -o containerd.tar.gz.sha256sum
  ## Check sha256
  if ! sha256sum -c containerd.tar.gz.sha256sum; then
    echo "sha256sum of containerd not correct!"
    exit 1
  fi
  ## Install
  tar Cxzf /usr/local "containerd-$CONTAINERD_VERSION-linux-amd64.tar.gz"
  ## Cleanup
  rm containerd*
  ## Set systemd service
  mkdir -p /usr/local/lib/systemd/system
  curl -fsSL "https://raw.githubusercontent.com/containerd/containerd/refs/tags/v$CONTAINERD_VERSION/containerd.service" -o /usr/local/lib/systemd/system/containerd.service
  systemctl enable --now containerd
  ## Configure the systemd cgroup driver
  mkdir -p /etc/containerd
  containerd config default > /etc/containerd/config.toml
  sed -i "s/SystemdCgroup = false/SystemdCgroup = true/g" /etc/containerd/config.toml

  # Nerdctl
  ## Download
  curl -fsSL -O "https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/{nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz,SHA256SUMS,SHA256SUMS.asc}"
  ## Validate
  gpg --keyserver keys.openpgp.org --recv-keys C020EA876CE4E06C7AB95AEF49524C6F9F638F1A
  if ! gpg --verify SHA256SUMS.asc SHA256SUMS; then
    echo "Could not verify nerdctl sha256sum file signature!"
    exit 1
  fi
  if ! grep "nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz" SHA256SUMS | sha256sum --check; then
    echo "Could not verify nerdctl sha256sum!"
    exit 1
  fi
  ## Install
  tar Cxzf /usr/local/bin "nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz"
  ## Cleanup
  rm "nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz"
  rm SHA256SUMS*

  # Runc
  ## Download
  curl -fsSL -O "https://github.com/opencontainers/runc/releases/download/v$RUNC_VERSION/runc.amd64"
  curl -fsSL -O "https://raw.githubusercontent.com/opencontainers/runc/refs/tags/v$RUNC_VERSION/runc.keyring"
  curl -fsSL -O "https://github.com/opencontainers/runc/releases/download/v$RUNC_VERSION/runc.amd64.asc"
  curl -fsSL -O "https://github.com/opencontainers/runc/releases/download/v$RUNC_VERSION/runc.sha256sum"
  ## Validate the file
  gpg --import --quiet runc.keyring
  ### Check runc.amd64 signature
  if ! gpg --verify runc.amd64.asc runc.amd64; then
    echo "Could not verify runc file signature!"
    exit 1
  fi
  ### Check runc.sha256sum signature
  if ! gpg --verify runc.sha256sum; then
    echo "Could not verify the runc.sha256sum signature!"
    exit 1
  fi
  ### Check runc.amd64 sha256sum
  if ! grep runc.amd64 runc.sha256sum | sha256sum --check; then
    echo "Could not verify the runc.amd64 sha256sum!"
    exit 1
  fi
  ## Install
  install -m 755 runc.amd64 /usr/local/sbin/runc
  ## Cleanup
  rm runc*

  # cni plugin
  ## Download
  curl -fsSL -O "https://github.com/containernetworking/plugins/releases/download/v$CNI_PLUGIN_VERSION/cni-plugins-linux-amd64-v$CNI_PLUGIN_VERSION.tgz{.sha256,}"
  ## Check sha256
  if ! sha256sum -c "cni-plugins-linux-amd64-v$CNI_PLUGIN_VERSION.tgz.sha256"; then
    echo "Could not verify the cni-plugin sha256sum!"
    exit 1
  fi
  ## Install
  mkdir -p /opt/cni/bin
  tar Cxzf /opt/cni/bin "cni-plugins-linux-amd64-v$CNI_PLUGIN_VERSION.tgz"
  ## Cleanup
  rm cni-plugins-linux-amd64*
}

# Kubeadm, kubelet, kubectl, helm
install_kubernetes_utilities() {
  local KUBERNETES_VERSION="1.35.1"
  local HELM_VERSION="4.1.1"

  # Download, verify and install utilities
  for utility in kubeadm kubelet kubectl; do
    ## Download
    curl -fsSL "https://dl.k8s.io/v$KUBERNETES_VERSION/bin/linux/amd64/$utility" -o "/usr/bin/$utility"
    curl -fsSL -O "https://dl.k8s.io/v$KUBERNETES_VERSION/bin/linux/amd64/$utility.{sha256,sig,cert}"
    ## Verify sha256
    if ! echo "$(cat $utility.sha256) /usr/bin/$utility" | sha256sum --check; then
      echo "Sha256sum of $utility is incorrect!"
      exit 1
    fi
    ## Verify file signature
    if ! cosign verify-blob "/usr/bin/$utility" \
        --signature "$utility.sig" \
        --certificate "$utility.cert" \
        --certificate-identity krel-staging@k8s-releng-prod.iam.gserviceaccount.com \
        --certificate-oidc-issuer https://accounts.google.com; then
      echo "Couldn't verify the file signature of $utility"
      exit 1
    fi
    ## Make sure binary is executable
    chmod +x "/usr/bin/$utility"
    ## Cleanup
    rm "$utility".{sha256,sig,cert}
  done

  # Install kubelet & kubeadm systemd service definitions
  curl -fsSL "https://raw.githubusercontent.com/kubernetes/release/v0.16.2/cmd/krel/templates/latest/kubelet/kubelet.service" \
          -o /usr/lib/systemd/system/kubelet.service
  sudo mkdir -p /usr/lib/systemd/system/kubelet.service.d
  curl -fsSL "https://raw.githubusercontent.com/kubernetes/release/v0.16.2/cmd/krel/templates/latest/kubeadm/10-kubeadm.conf" \
          -o /usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf
  # Ensure kubelet runs on startup
  systemctl enable kubelet.service

  # Prepare the system with the required kubeadm images
  kubeadm config images pull

  # Helm
  ## Download
  curl -fsSL -O "https://get.helm.sh/helm-v$HELM_VERSION-linux-amd64.tar.gz{.sha256sum,}"
  curl -fsSL -O "https://github.com/helm/helm/releases/download/v$HELM_VERSION/helm-v$HELM_VERSION-linux-amd64.tar.gz.{asc,sha256sum.asc}"
  curl -fsSL "https://raw.githubusercontent.com/helm/helm/refs/tags/v$HELM_VERSION/KEYS" \
          -o "helm-v$HELM_VERSION-KEYS"
  ## Verify signature
  gpg --keyserver keys.openpgp.org --recv-keys BF888333D96A1C18E2682AAED79D67C9EC016739
  curl -fsSL "https://raw.githubusercontent.com/helm/helm/refs/tags/v$HELM_VERSION/KEYS" | gpg --import --quiet
  if ! gpg --verify "helm-v$HELM_VERSION-linux-amd64.tar.gz.asc" \
                    "helm-v$HELM_VERSION-linux-amd64.tar.gz"; then
    echo "Couldn't verify the file signature of helm binary file"
    exit 1
  fi
  if ! gpg --verify "helm-v$HELM_VERSION-linux-amd64.tar.gz.sha256sum.asc" \
                    "helm-v$HELM_VERSION-linux-amd64.tar.gz.sha256sum"; then
    echo "Couldn't verify the file signature of helm sha256 file"
    exit 1
  fi
  ## Verify sha256
  if ! sha256sum -c helm-v$HELM_VERSION-linux-amd64.tar.gz.sha256sum; then
    echo "Sha256sum of helm is incorrect!"
    exit 1
  fi
  ## Install
  tar zxf helm-v4.1.1-linux-amd64.tar.gz --strip-components=1 -C /usr/local/bin linux-amd64/helm
  ## Cleanup
  rm helm-v"$HELM_VERSION"*
}

# Use keepalived+haproxy to configure ha between control-plane nodes using a VIP
configure_ha() {
  # Keepalived configuration
  {
    echo "global_defs {"
    echo "  script_user root"
    echo "  enable_script_security"
    echo "}"
    echo
    echo "vrrp_script chk_haproxy {"
    echo "  script \"/etc/keepalived/check_apiserver.sh\""
    echo "  interval 2"
    echo "  weight -20"
    echo "  fall 3"
    echo "  rise 2"
    echo "}"
    echo
    echo "vrrp_instance VI_1 {"
    echo "  @host01 state MASTER"
    echo "  @host02 state BACKUP"
    echo "  @host03 state BACKUP"
    echo "  interface ens18"
    echo "  advert_int 1"
    echo "  virtual_router_id 188"
    echo
    echo "  @host01 priority 110"
    echo "  @host02 priority 105"
    echo "  @host03 priority 100"
    echo
    echo "  authentication {"
    echo "    auth_type PASS"
    echo "    auth_pass k8s-ha"
    echo "  }"
    echo
    echo "  @host01 unicast_src_ip 172.16.3.11"
    echo "  @host02 unicast_src_ip 172.16.3.12"
    echo "  @host03 unicast_src_ip 172.16.3.13"
    echo "  unicast_peer {"
    echo "      @^host01 172.16.3.11"
    echo "      @^host02 172.16.3.12"
    echo "      @^host03 172.16.3.13"
    echo "  }"
    echo
    echo "  virtual_ipaddress {"
    echo "    172.16.3.10"
    echo "  }"
    echo
    echo "  track_script {"
    echo "    chk_haproxy"
    echo "  }"
    echo "}"
  } > /etc/keepalived/keepalived.conf
  {
    echo '#!/bin/sh'
    echo "errorExit() {"
    echo '  echo "*** $*" 1>&2'
    echo "  exit 1"
    echo "}"
    echo
    echo "# Try to connect to the local API server"
    echo "curl --silent --max-time 5 -k https://localhost:6443/healthz || errorExit 'Error GET https://localhost:6443/healthz'"
  } > /etc/keepalived/check_apiserver.sh
  chmod +x /etc/keepalived/check_apiserver.sh
  ## We enable the haproxy only on master nodes when provisioning the cluster
  systemctl disable --now haproxy

  # haproxy configuration
  {
    echo "global"
    echo "  log /dev/log local0"
    echo "  log /dev/log local1 notice"
    echo "  maxconn 2000"
    echo "  chroot /var/lib/haproxy"
    echo "  stats socket /run/haproxy/admin.sock mode 660 level admin"
    echo "  stats timeout 30s"
    echo "  user haproxy"
    echo "  group haproxy"
    echo "  daemon"
    echo
    echo "defaults"
    echo "  log	    global"
    echo "  mode    tcp"
    echo "  option  tcplog"
    echo "  option  dontlognull"
    echo "  option  redispatch"
    echo "  retries 3"
    echo "  maxconn 2000"
    echo "  timeout connect 30s"
    echo "  timeout client  1h"
    echo "  timeout server  1h"
    echo "  timeout check   10s"
    echo
    echo "frontend kubernetes-api"
    echo "  bind *:8443             # HAProxy listens on 8443 to avoid conflict with API server"
    echo "  default_backend kubernetes-master-nodes"
    echo
    echo "backend kubernetes-master-nodes"
    echo "  balance roundrobin"
    echo "  option tcp-check"
    echo "  server host01 172.16.3.11:6443 check inter 2s fall 3 rise 2"
    echo "  server host02 172.16.3.12:6443 check inter 2s fall 3 rise 2"
    echo "  server host03 172.16.3.13:6443 check inter 2s fall 3 rise 2"
  } > /etc/haproxy/haproxy.cfg
  ## We enable the haproxy only on master nodes when provisioning the cluster
  systemctl disable --now haproxy
}

# Install the required tools for the CNI of the kubernetes cluster (the CNI itself will only be installed after the cluster is set up)
install_cni() {
  local CILIUM_VERSION=1.19.1
  local CILIUM_CLI_VERSION=0.19.2

  # Helm chart
  ## Validate helm chart
  if ! cosign verify \
      --certificate-identity-regexp='https://github.com/cilium/cilium/.*' \
      --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
      "quay.io/cilium/charts/cilium:$CILIUM_VERSION" 1>/dev/null; then
    echo "Could not verify Cilium helm chart version $CILIUM_VERSION!"
    exit 1
  fi
  ## Configure helm chart
  mkdir -p /etc/kubernetes/thirdparty/cilium
  {
    echo "k8sServiceHost: 172.16.3.10"
    echo "k8sServicePort: 8443"
    echo
    echo "rollOutCiliumPods: true"
    echo
    echo "resources:"
    echo "  limits:"
    echo "    cpu: 250m"
    echo "    memory: 512Gi"
    echo "  requests:"
    echo "    cpu: 50m"
    echo "    memory: 100Mi"
    echo
    echo "annotateK8sNode: true"
    echo
    echo "l2announcements:"
    echo "  enabled: false"
    echo
    echo "l2podAnnouncements:"
    echo "  enabled: false"
    echo
    echo "bgpControlPlane:"
    echo "  enabled: true"
    echo
    echo "pmtuDiscovery:"
    echo "  enabled: true"
    echo
    echo "bpf:"
    echo "  distributedLRU:"
    echo "    enabled: true"
    echo "  lbExternalClusterIP: true"
    echo "  masquerade: true"
    echo
    echo "cni:"
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 10Mi"
    echo "    limits:"
    echo "      cpu: 100m"
    echo "      memory: 100Mi"
    echo
    echo "ciliumEndpointSlice:"
    echo "  enabled: true"
    echo
    echo "envoyConfig:"
    echo "  enabled: true"
    echo
    echo "ingressController:"
    echo "  enabled: true"
    echo "  default: true"
    echo
    echo "gatewayAPI:"
    echo "  enabled: true"
    echo
    echo "encryption:"
    echo "  enabled: true"
    echo "  type: wireguard"
    echo "  nodeEncryption: true"
    echo "  egress:"
    echo "    enabled: true"
    echo "  ingress:"
    echo "    enabled: true"
    echo
    echo "socketLB:"
    echo "  enabled: true"
    echo
    echo "certgen:"
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo "    limits:"
    echo "      cpu: 150m"
    echo "      memory: 250Mi"
    echo
    echo "hubble:"
    echo "  metrics:"
    echo "    serviceMonitor:"
    echo "      enabled: true"
    echo "    dashboards:"
    echo "      enabled: true"
    echo "    dynamic:"
    echo "      enabled: true"
    echo "  relay:"
    echo "    enabled: true"
    echo "    rollOutPods: true"
    echo "    resources:"
    echo "      limits:"
    echo "        cpu: 250m"
    echo "        memory: 250Mi"
    echo "      requests:"
    echo "        cpu: 50m"
    echo "        memory: 50Mi"
    echo "    replicas: 3"
    echo "    sortBufferLenMax: 100"
    echo "    sortBufferDrainTimeout: 1s"
    echo "    prometheus:"
    echo "      enabled: true"
    echo "      serviceMonitor:"
    echo "        enabled: true"
    echo "    pprof:"
    echo "      enabled: true"
    echo "  ui:"
    echo "    enabled: true"
    echo "    rollOutPods: true"
    echo "    backend:"
    echo "      livenessProbe:"
    echo "        enabled: false # Broken, see https://github.com/cilium/cilium/pull/43607"
    echo "      readinessProbe:"
    echo "        enabled: false # Broken, see https://github.com/cilium/cilium/pull/43607"
    echo "      resources:"
    echo "        limits:"
    echo "          cpu: 250m"
    echo "          memory: 250Mi"
    echo "        requests:"
    echo "          cpu: 50m"
    echo "          memory: 64Mi"
    echo "    frontend:"
    echo "      resources:"
    echo "        limits:"
    echo "          cpu: 250m"
    echo "          memory: 150Mi"
    echo "        requests:"
    echo "          cpu: 50m"
    echo "          memory: 64Mi"
    echo "    replicas: 2"
    echo "    ingress:"
    echo "      enabled: true"
    echo "    dynamic:"
    echo "      enabled: true"
    echo
    echo "ipMasqAgent:"
    echo "  enabled: false"
    echo "enableIPv4Masquerade: true"
    echo
    echo "kubeProxyReplacement: true"
    echo
    echo "l2NeighDiscovery:"
    echo "  enabled: true"
    echo
    echo "localRedirectPolicies:"
    echo "  enabled: true"
    echo
    echo "logSystemLoad: true"
    echo
    echo "monitor:"
    echo "  enabled: true"
    echo
    echo "loadBalancer:"
    echo "  acceleration: disabled"
    echo
    echo "l7:"
    echo "  backend: envoy"
    echo "  algorithm: least_request"
    echo
    echo "pprof:"
    echo "  enabled: true"
    echo
    echo "prometheus:"
    echo "  metricsService: true"
    echo "  enabled: true"
    echo
    echo "dashboards:"
    echo "  enabled: true"
    echo
    echo "envoy:"
    echo "  rollOutPods: true"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 250m"
    echo "      memory: 250Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo "  prometheus:"
    echo "    serviceMonitor:"
    echo "      enabled: true"
    echo
    echo "operator:"
    echo "  rollOutPods: true"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 250m"
    echo "      memory: 250Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo "  pprof:"
    echo "    enabled: true"
    echo "  prometheus:"
    echo "    metricsService: true"
    echo "    serviceMonitor:"
    echo "      enabled: true"
    echo "  dashboards:"
    echo "    enabled: true"
    echo
    echo "cgroup:"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 100m"
    echo "      memory: 128Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 64Mi"
  } > /etc/kubernetes/thirdparty/cilium/values.yaml
  ## Download images for helm chart
  local cilium_images
  cilium_images="$( { helm template cilium oci://quay.io/cilium/charts/cilium --values /etc/kubernetes/thirdparty/cilium/values.yaml --set prometheus.serviceMonitor.trustCRDsExist=true --version 1.19.1 2>&1 1>&3 | grep -vE '^(Pulled:|Digest:)' >&2; } 3>&1 | grep -oE '(quay.*)' | tr -d '"' | sort -u )"
  for image in $cilium_images; do
    nerdctl pull -q "$image"
  done

  # cilium CLI
  ## Download
  curl -fsSL -O "https://github.com/cilium/cilium-cli/releases/download/v$CILIUM_CLI_VERSION/cilium-linux-amd64.tar.gz{,.sha256sum}"
  ## Verify
  if ! sha256sum -c cilium-linux-amd64.tar.gz.sha256sum; then
    echo "Cloud not verify sha256sum of cilium cli!"
    exit 1
  fi
  ## Install
  tar Cxzf /usr/local/bin cilium-linux-amd64.tar.gz
  ## Cleanup
  rm cilium*
}

# Install Prometheus custom resource definition (used for other helm charts)
prometheus_crd()
{
  local PROMETHEUS_OPERATOR_VERSION="0.89.0"

  mkdir -p /etc/kubernetes/thirdparty/prometheus
  curl -fsSL "https://github.com/prometheus-operator/prometheus-operator/releases/download/v$PROMETHEUS_OPERATOR_VERSION/bundle.yaml" -o /etc/kubernetes/thirdparty/prometheus/prometheus.yaml

  local prometheus_images
  prometheus_images="$(grep -oE '(quay.*)' /etc/kubernetes/thirdparty/prometheus/prometheus.yaml)"

  for image in $prometheus_images; do
    nerdctl pull -q "$image"
  done
}

# Install GatewayAPI custom resource definition (used for Cilium CNI)
gatewayapi_crd() {
  local GATEWAYAPI_VERSION="1.4.1"
  local GATEWAYAPI_MANIFEST_LOCATION="/etc/kubernetes/thirdparty/gatewayapi"

  mkdir -p "$GATEWAYAPI_MANIFEST_LOCATION"

  for item in gatewayclasses gateways httproutes referencegrants grpcroutes; do
    curl -fsSL "https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v$GATEWAYAPI_VERSION/config/crd/standard/gateway.networking.k8s.io_$item.yaml" -o "$GATEWAYAPI_MANIFEST_LOCATION/gateway.networking.k8s.io_$item.yaml"
  done

  curl -fsSL "https://raw.githubusercontent.com/kubernetes-sigs/gateway-api/v$GATEWAYAPI_VERSION/config/crd/experimental/gateway.networking.k8s.io_tlsroutes.yaml" -o "$GATEWAYAPI_MANIFEST_LOCATION/gateway.networking.k8s.io_tlsroutes.yaml"
}

# Install cert-manager operator helm chart
cert_manager() {
  local CERT_MANAGER_VERSION
  local CERT_MANAGER_CONFIG_DIR

  CERT_MANAGER_VERSION="1.20.1"
  CERT_MANAGER_CONFIG_DIR="/etc/kubernetes/thirdparty/cert-manager"

  mkdir -p "$CERT_MANAGER_CONFIG_DIR"

  curl -fsSL https://cert-manager.io/public-keys/cert-manager-keyring-2021-09-20-1020CF3C033D4F35BAE1C19E1226061C665DF13E.gpg -o "$CERT_MANAGER_CONFIG_DIR/cert-manager-keyring.gpg"

  {
    echo "crds:"
    echo "  # This option decides if the CRDs should be installed"
    echo "  # as part of the Helm installation."
    echo "  enabled: true"
    echo
    echo "# The number of replicas of the cert-manager controller to run."
    echo "replicaCount: 3"
    echo
    echo "# Deployment update strategy for the cert-manager controller deployment."
    echo "strategy:"
    echo "  type: RollingUpdate"
    echo "  rollingUpdate:"
    echo "    maxSurge: 0"
    echo "    maxUnavailable: 1"
    echo
    echo "podDisruptionBudget:"
    echo "  # Enable or disable the PodDisruptionBudget resource."
    echo "  enabled: true"
    echo
    echo "  # This configures the maximum unavailable pods for disruptions"
    echo "  maxUnavailable: 1"
    echo
    echo "  # This configures how to act with unhealthy pods during eviction"
    echo "  unhealthyPodEvictionPolicy: AlwaysAllow"
    echo
    echo "# Resources to provide to the cert-manager controller pod."
    echo "resources:"
    echo "  requests:"
    echo "    cpu: 50m"
    echo "    memory: 50Mi"
    echo
    echo "# Pod Security Context."
    echo "securityContext:"
    echo "  runAsNonRoot: true"
    echo "  seccompProfile:"
    echo "    type: RuntimeDefault"
    echo
    echo "# Container Security Context to be set on the controller component container."
    echo "containerSecurityContext:"
    echo "  allowPrivilegeEscalation: false"
    echo "  capabilities:"
    echo "    drop:"
    echo "    - ALL"
    echo "  readOnlyRootFilesystem: true"
    echo
    echo "# Enables default network policies for cert-manager."
    echo "networkPolicy:"
    echo "  # Create network policies for cert-manager."
    echo "  enabled: true"
    echo
    echo "# LivenessProbe settings for the controller container of the controller Pod."
    echo "livenessProbe:"
    echo "  enabled: true"
    echo "  initialDelaySeconds: 10"
    echo "  periodSeconds: 10"
    echo "  timeoutSeconds: 15"
    echo "  successThreshold: 1"
    echo "  failureThreshold: 8"
    echo
    echo "prometheus:"
    echo "  # Enable Prometheus monitoring for the cert-manager controller and webhook."
    echo "  enabled: true"
    echo
    echo "  servicemonitor:"
    echo "    # Create a ServiceMonitor to add cert-manager to Prometheus."
    echo "    enabled: true"
    echo
    echo "    # The target port to set on the ServiceMonitor. This must match the port that the"
    echo "    # cert-manager controller is listening on for metrics."
    echo "    targetPort: http-metrics"
    echo
    echo "    # The path to scrape for metrics."
    echo "    path: /metrics"
    echo
    echo "    # The interval to scrape metrics."
    echo "    interval: 60s"
    echo
    echo "    # The timeout before a metrics scrape fails."
    echo "    scrapeTimeout: 30s"
    echo
    echo "webhook:"
    echo "  # Number of replicas of the cert-manager webhook to run."
    echo "  replicaCount: 3"
    echo
    echo "  # The update strategy for the cert-manager webhook deployment."
    echo "  strategy:"
    echo "    type: RollingUpdate"
    echo "    rollingUpdate:"
    echo "      maxSurge: 0"
    echo "      maxUnavailable: 1"
    echo
    echo "  # Pod Security Context to be set on the webhook component Pod."
    echo "  securityContext:"
    echo "    runAsNonRoot: true"
    echo "    seccompProfile:"
    echo "      type: RuntimeDefault"
    echo
    echo "  # Container Security Context to be set on the webhook component container."
    echo "  containerSecurityContext:"
    echo "    allowPrivilegeEscalation: false"
    echo "    capabilities:"
    echo "      drop:"
    echo "      - ALL"
    echo "    readOnlyRootFilesystem: true"
    echo
    echo "  podDisruptionBudget:"
    echo "    # Enable or disable the PodDisruptionBudget resource."
    echo "    enabled: true"
    echo
    echo "    # This property configures the maximum unavailable pods for disruptions"
    echo "    maxUnavailable: 1"
    echo
    echo "  # Resources to provide to the cert-manager webhook pod."
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo
    echo "  # Liveness probe values."
    echo "  livenessProbe:"
    echo "    failureThreshold: 3"
    echo "    initialDelaySeconds: 60"
    echo "    periodSeconds: 10"
    echo "    successThreshold: 1"
    echo "    timeoutSeconds: 1"
    echo
    echo "  # Readiness probe values."
    echo "  readinessProbe:"
    echo "    failureThreshold: 3"
    echo "    initialDelaySeconds: 5"
    echo "    periodSeconds: 5"
    echo "    successThreshold: 1"
    echo "    timeoutSeconds: 1"
    echo
    echo "  # Enables default network policies for webhooks."
    echo "  networkPolicy:"
    echo "    # Create network policies for the webhooks."
    echo "    enabled: true"
    echo
    echo "cainjector:"
    echo
    echo "  # The number of replicas of the cert-manager cainjector to run."
    echo "  replicaCount: 3"
    echo
    echo "  # Deployment update strategy for the cert-manager cainjector deployment."
    echo "  strategy:"
    echo "    type: RollingUpdate"
    echo "    rollingUpdate:"
    echo "      maxSurge: 0"
    echo "      maxUnavailable: 1"
    echo
    echo "  # Pod Security Context to be set on the cainjector component Pod"
    echo "  securityContext:"
    echo "    runAsNonRoot: true"
    echo "    seccompProfile:"
    echo "      type: RuntimeDefault"
    echo
    echo "  # Container Security Context to be set on the cainjector component container"
    echo "  containerSecurityContext:"
    echo "    allowPrivilegeEscalation: false"
    echo "    capabilities:"
    echo "      drop:"
    echo "      - ALL"
    echo "    readOnlyRootFilesystem: true"
    echo
    echo "  # Enables default network policies for cainjector."
    echo "  networkPolicy:"
    echo "    # Create network policies for the cainjector."
    echo "    enabled: true"
    echo
    echo "  podDisruptionBudget:"
    echo "    # Enable or disable the PodDisruptionBudget resource."
    echo "    enabled: true"
    echo
    echo "    maxUnavailable: 1"
    echo
    echo "  # Resources to provide to the cert-manager cainjector pod."
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo
    echo "startupapicheck:"
    echo "  # Enables the startup api check."
    echo "  enabled: true"
    echo
    echo "  # Pod Security Context to be set on the startupapicheck component Pod."
    echo "  securityContext:"
    echo "    runAsNonRoot: true"
    echo "    seccompProfile:"
    echo "      type: RuntimeDefault"
    echo
    echo "  # Container Security Context to be set on the controller component container."
    echo "  containerSecurityContext:"
    echo "    allowPrivilegeEscalation: false"
    echo "    capabilities:"
    echo "      drop:"
    echo "      - ALL"
    echo "    readOnlyRootFilesystem: true"
    echo
    echo "  # Resources to provide to the cert-manager controller pod."
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
  } > "$CERT_MANAGER_CONFIG_DIR/values.yaml"

  # Download cert-manager images
  for image in $( { helm template cert-manager oci://quay.io/jetstack/charts/cert-manager --values "$CERT_MANAGER_CONFIG_DIR/values.yaml" --version "v$CERT_MANAGER_VERSION" --verify --keyring /etc/kubernetes/thirdparty/cert-manager/cert-manager-keyring.gpg 2>&1 1>&3 | grep -vE '^(Pulled:|Digest:)' >&2; } 3>&1 | grep 'image: ' | awk '{print $2}' |  tr -d '"' | sort -u ); do
    nerdctl pull -q "$image"
  done
}

# Install External Secrets Manager to use Bitwarden Secrets Manager to pull secrets into the cluster
eso_bws() {
  local EXTERNAL_SECRETS_OPERATOR_VERSION
  local EXTERNAL_SECRETS_OPERATOR_CONFIG_DIR

  EXTERNAL_SECRETS_OPERATOR_VERSION="2.2.0"
  EXTERNAL_SECRETS_OPERATOR_CONFIG_DIR="/etc/kubernetes/thirdparty/external-secrets-operator"

  mkdir -p "$EXTERNAL_SECRETS_OPERATOR_CONFIG_DIR"

  helm repo add external-secrets https://charts.external-secrets.io
  helm repo update

  {
    echo "apiVersion: cert-manager.io/v1"
    echo "kind: Issuer"
    echo "metadata:"
    echo "  name: self-signed"
    echo "  namespace: external-secrets"
    echo "spec:"
    echo "  selfSigned: {}"
    echo "---"
    echo "apiVersion: cert-manager.io/v1"
    echo "kind: Certificate"
    echo "metadata:"
    echo "  name: bitwarden-tls-certs"
    echo "  namespace: external-secrets"
    echo "spec:"
    echo "  secretName: bitwarden-tls-certs"
    echo "  issuerRef:"
    echo "    kind: \"Issuer\""
    echo "    name: \"self-signed\""
    echo "  commonName: bitwarden-sdk-server.external-secrets.svc.cluster.local"
    echo "  dnsNames:"
    echo "    - bitwarden-sdk-server.external-secrets.svc.cluster.local"
    echo "  usages:"
    echo "    - server auth"
    echo "    - client auth"
    echo "  isCA: true"
  } > "$EXTERNAL_SECRETS_OPERATOR_CONFIG_DIR/certificate-resources.yaml"

  {
    echo "replicaCount: 3"
    echo
    echo "bitwarden-sdk-server:"
    echo "  enabled: true"
    echo
    echo "# -- If set, install and upgrade CRDs through helm chart."
    echo "installCRDs: true"
    echo
    echo "# -- If true, external-secrets will perform leader election between instances to ensure no more"
    echo "# than one instance of external-secrets operates at a time."
    echo "leaderElect: true"
    echo
    echo "# -- If true external secrets will use recommended kubernetes"
    echo "# annotations as prometheus metric labels."
    echo "extendedMetricLabels: true"
    echo
    echo "# -- if true, HTTP2 will be enabled for the services created by all controllers, curently metrics and webhook."
    echo "enableHTTP2: true"
    echo
    echo "resources:"
    echo "  requests:"
    echo "    cpu: 50m"
    echo "    memory: 50Mi"
    echo
    echo "serviceMonitor:"
    echo "  # -- Specifies whether to create a ServiceMonitor resource for collecting Prometheus metrics"
    echo "  enabled: true"
    echo
    echo "  # -- How should we react to missing CRD \"monitoring.coreos.com/v1/ServiceMonitor\""
    echo "  renderMode: failIfMissing"
    echo
    echo "  # -- Let prometheus add an exported_ prefix to conflicting labels"
    echo "  honorLabels: true"
    echo
    echo "metrics:"
    echo
    echo "  listen:"
    echo "    port: 8080"
    echo "    secure:"
    echo "      enabled: true"
    echo
    echo "grafanaDashboard:"
    echo "  # -- If true creates a Grafana dashboard."
    echo "  enabled: true"
    echo
    echo "livenessProbe:"
    echo "  # -- Enabled determines if the liveness probe should be used or not. By default it's disabled."
    echo "  enabled: true"
    echo
    echo "readinessProbe:"
    echo "  # -- Determines whether the readiness probe is enabled. Disabled by default. Enabling this will auto-start the health server (--live-addr) even if livenessProbe is disabled. Health server address/port are configured via livenessProbe.spec.address and livenessProbe.spec.port."
    echo "  enabled: true"
    echo
    echo "# -- Pod disruption budget - for more details see https://kubernetes.io/docs/concepts/workloads/pods/disruptions/"
    echo "podDisruptionBudget:"
    echo "  enabled: true"
    echo "  minAvailable: 2    # @schema type:[integer, string]"
    echo
    echo "webhook:"
    echo "  replicaCount: 3"
    echo
    echo "  certManager:"
    echo "    # -- Enabling cert-manager support will disable the built in secret and"
    echo "    # switch to using cert-manager (installed separately) to automatically issue"
    echo "    # and renew the webhook certificate. This chart does not install"
    echo "    # cert-manager for you, See https://cert-manager.io/docs/"
    echo "    enabled: true"
    echo "    cert:"
    echo "      issuerRef:"
    echo "        group: cert-manager.io"
    echo "        kind: \"Issuer\""
    echo "        name: \"self-signed\""
    echo "      # -- Specific settings on the privateKey and its generation"
    echo "      privateKey:"
    echo "        rotationPolicy: Always"
    echo "        algorithm: RSA"
    echo "        size: 4096"
    echo
    echo "  # -- Pod disruption budget - for more details see https://kubernetes.io/docs/concepts/workloads/pods/disruptions/"
    echo "  podDisruptionBudget:"
    echo "    enabled: true"
    echo "    minAvailable: 2"
    echo
    echo "  podSecurityContext:"
    echo "    enabled: true"
    echo
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo
    echo "certController:"
    echo "  create: false"
  } > "$EXTERNAL_SECRETS_OPERATOR_CONFIG_DIR/values.yaml"

  {
    echo 'apiVersion: external-secrets.io/v1'
    echo 'kind: ClusterSecretStore'
    echo 'metadata:'
    echo '  name: bitwarden-secretsmanager'
    echo 'spec:'
    echo '  provider:'
    echo '    bitwardensecretsmanager:'
    echo '      apiURL: https://api.bitwarden.com'
    echo '      identityURL: https://identity.bitwarden.com'
    echo '      auth:'
    echo '        secretRef:'
    echo '          credentials:'
    echo '            name: bitwarden-access-token'
    echo '            namespace: external-secrets'
    echo '            key: token'
    echo '      bitwardenServerSDKURL: https://bitwarden-sdk-server.external-secrets.svc.cluster.local:9998'
    # shellcheck disable=SC2016
    echo '      caBundle: $BITWARDEN_CA_TLS_CERT'
    # shellcheck disable=SC2016
    echo '      organizationID: $BITWARDEN_ORGANIZATION_ID'
    # shellcheck disable=SC2016
    echo '      projectID: $BITWARDEN_PROJECT_ID'
  } > "$EXTERNAL_SECRETS_OPERATOR_CONFIG_DIR/cluster-secret-store.yaml"

  # Download external-secrets images
  for image in $(helm template external-secrets external-secrets/external-secrets --values "$EXTERNAL_SECRETS_OPERATOR_CONFIG_DIR/values.yaml" --version "$EXTERNAL_SECRETS_OPERATOR_VERSION" | grep 'image: ' | awk '{print $2}' |  tr -d '"' | sort -u); do
    nerdctl pull -q "$image"
  done
}

# Install ArgoCD
argocd() {
  local ARGOCD_VERSION
  local ARGOCD_CONFIG_DIR

  ARGOCD_VERSION="9.4.17"
  ARGOCD_CONFIG_DIR="/etc/kubernetes/thirdparty/argocd"

  mkdir -p "$ARGOCD_CONFIG_DIR"

  {
    echo "## Globally shared configuration"
    echo "global:"
    echo
    echo "  # -- Add Prometheus scrape annotations to all metrics services. This can be used as an alternative to the ServiceMonitors."
    echo "  addPrometheusAnnotations: true"
    echo
    echo "  # -- Toggle and define pod-level security context."
    echo "  securityContext:"
    echo "    runAsUser: 999"
    echo "    runAsGroup: 999"
    echo "    fsGroup: 999"
    echo
    echo "  # Default network policy rules used by all components"
    echo "  networkPolicy:"
    echo "    # -- Create NetworkPolicy objects for all components"
    echo "    create: true"
    echo "    # -- Default deny all ingress traffic"
    echo "    defaultDenyIngress: true"
    echo
    echo "  # -- Deployment strategy for the all deployed Deployments"
    echo "  deploymentStrategy:"
    echo "    type: RollingUpdate"
    echo "    rollingUpdate:"
    echo "      maxSurge: 1"
    echo "      maxUnavailable: 1"
    echo
    echo "## Argo Configs"
    echo "configs:"
    echo "  # General Argo CD configuration. Any values you put under \`.configs.cm\` are passed to argocd-cm ConfigMap."
    echo "  ## Ref: https://github.com/argoproj/argo-cd/blob/master/docs/operator-manual/argocd-cm.yaml"
    echo "  cm:"
    echo "    # -- Create the argocd-cm configmap for [declarative setup]"
    echo "    create: true"
    echo
    echo "    # -- Timeout to discover if a new manifests version got published to the repository"
    echo "    timeout.reconciliation: 60s"
    echo
    echo "    # -- Maximum jitter added to the reconciliation timeout to spread out refreshes and reduce repo-server load"
    echo "    timeout.reconciliation.jitter: 30s"
    echo
    echo "    # -- Timeout to refresh application data as well as target manifests cache"
    echo "    timeout.hard.reconciliation: 0s"
    echo
    echo "  params:"
    echo "    server.insecure: true"
    echo
    echo "  # -- Repositories list to be used by applications"
    echo "  repositories:"
    echo "    kubemite-gitops:"
    echo "      url: https://github.com/kubemite/gitops.git"
    echo
    echo "  # Argo CD sensitive data"
    echo "  # Ref: https://argo-cd.readthedocs.io/en/stable/operator-manual/user-management/#sensitive-data-and-sso-client-secrets"
    echo "  secret:"
    echo "    # -- Create the argocd-secret"
    echo "    createSecret: false"
    echo
    echo "# -- Array of extra K8s manifests to deploy"
    echo "## Note: Supports use of custom Helm templates"
    echo "extraObjects:"
    echo "  - apiVersion: external-secrets.io/v1"
    echo "    kind: ExternalSecret"
    echo "    metadata:"
    echo "      name: argocd-secret"
    echo "      namespace: argocd"
    echo "      labels:"
    echo "        app.kubernetes.io/name: argocd-secret"
    echo "        app.kubernetes.io/part-of: argocd"
    echo "    spec:"
    echo "      refreshInterval: 1h0m0s"
    echo "      secretStoreRef:"
    echo "        name: bitwarden-secretsmanager"
    echo "        kind: ClusterSecretStore"
    echo "      data:"
    echo "        - secretKey: admin.password"
    echo "          remoteRef:"
    echo "            key: b39b8bad-ed60-473c-a23d-b42200cf959e"
    echo "        - secretKey: server.secretkey"
    echo "          remoteRef:"
    echo "            key: 43c29779-189d-4977-a5b7-b42201493873"
    echo
    echo "## Application controller"
    echo "controller:"
    echo
    echo "  # -- The number of application controller pods to run."
    echo "  # Additional replicas will cause sharding of managed clusters across number of replicas."
    echo "  ## With dynamic cluster distribution turned on, sharding of the clusters will gracefully"
    echo "  ## rebalance if the number of replica's changes or one becomes unhealthy. (alpha)"
    echo "  replicas: 3"
    echo
    echo "  ## Application controller Pod Disruption Budget"
    echo "  ## Ref: https://kubernetes.io/docs/tasks/run-application/configure-pdb/"
    echo "  pdb:"
    echo "    # -- Deploy a [PodDisruptionBudget] for the application controller"
    echo "    enabled: true"
    echo "    # -- Number of pods that are unavailable after eviction as number or percentage (eg.: 50%)"
    echo "    maxUnavailable: 1"
    echo
    echo "  ## Application controller emptyDir volumes"
    echo "  emptyDir:"
    echo "    # -- EmptyDir size limit for application controller"
    echo "    sizeLimit: 1Gi"
    echo
    echo "  # -- Resource limits and requests for the application controller pods"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 250"
    echo "      memory: 256Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo
    echo "  ## Application controller metrics configuration"
    echo "  metrics:"
    echo "    # -- Deploy metrics service"
    echo "    enabled: true"
    echo "    serviceMonitor:"
    echo "      # -- Enable a prometheus ServiceMonitor"
    echo "      enabled: true"
    echo "      # -- Prometheus ServiceMonitor interval"
    echo "      interval: 30s"
    echo "      # -- When true, honorLabels preserves the metric's labels when they collide with the target's labels."
    echo "      honorLabels: true"
    echo "      # -- Prometheus ServiceMonitor selector"
    echo "      selector: {}"
    echo "        # prometheus: kube-prometheus"
    echo
    echo "    rules:"
    echo "      # -- Deploy a PrometheusRule for the application controller"
    echo "      enabled: true"
    echo "      # -- PrometheusRule namespace"
    echo "      namespace: \"\""
    echo "      # -- PrometheusRule selector"
    echo "      selector: {}"
    echo "        # prometheus: kube-prometheus"
    echo
    echo "      # -- PrometheusRule.Spec for the application controller"
    echo "      spec:"
    echo "        - alert: ArgoAppMissing"
    echo "          expr: |"
    echo "            absent(argocd_app_info) == 1"
    echo "          for: 15m"
    echo "          labels:"
    echo "            severity: critical"
    echo "          annotations:"
    echo "            summary: \"[Argo CD] No reported applications\""
    echo "            description: >"
    echo "              Argo CD has not reported any applications data for the past 15 minutes which"
    echo "              means that it must be down or not functioning properly.  This needs to be"
    echo "              resolved for this cloud to continue to maintain state."
    echo "        - alert: ArgoAppNotSynced"
    echo "          expr: |"
    echo "            argocd_app_info{sync_status!=\"Synced\"} == 1"
    echo "          for: 12h"
    echo "          labels:"
    echo "            severity: warning"
    echo "          annotations:"
    # shellcheck disable=SC2016
    echo '            summary: "[{{`{{$labels.name}}`}}] Application not synchronized"'
    echo "            description: >"
    # shellcheck disable=SC2016
    echo '              The application [{{`{{$labels.name}}`}} has not been synchronized for over'
    echo "              12 hours which means that the state of this cloud has drifted away from the"
    echo "              state inside Git."
    echo
    echo "  # Default application controller's network policy"
    echo "  networkPolicy:"
    echo "    # -- Default network policy rules used by application controller"
    echo "    create: true"
    echo
    echo "## Dex"
    echo "dex:"
    echo "  enabled: false"
    echo
    echo "## Redis"
    echo "redis:"
    echo "  # -- Enable redis"
    echo "  enabled: true"
    echo "  ## Redis Pod Disruption Budget"
    echo "  pdb:"
    echo "    # -- Deploy a [PodDisruptionBudget] for the Redis"
    echo "    enabled: true"
    echo "    # -- Number of pods that are unavailble after eviction as number or percentage (eg.: 50%)."
    echo "    maxUnavailable: 1"
    echo
    echo "  ## Prometheus redis-exporter sidecar"
    echo "  exporter:"
    echo "    # -- Enable Prometheus redis-exporter sidecar"
    echo "    enabled: true"
    echo
    echo "    ## Probes for Redis exporter (optional)"
    echo "    readinessProbe:"
    echo "      # -- Enable Kubernetes liveness probe for Redis exporter (optional)"
    echo "      enabled: true"
    echo "    livenessProbe:"
    echo "      # -- Enable Kubernetes liveness probe for Redis exporter"
    echo "      enabled: true"
    echo
    echo "    # -- Resource limits and requests for redis-exporter sidecar"
    echo "    resources:"
    echo "      limits:"
    echo "        cpu: 50m"
    echo "        memory: 64Mi"
    echo "      requests:"
    echo "        cpu: 10m"
    echo "        memory: 32Mi"
    echo
    echo "  ## Probes for Redis server (optional)"
    echo "  readinessProbe:"
    echo "    # -- Enable Kubernetes liveness probe for Redis server"
    echo "    enabled: true"
    echo "  livenessProbe:"
    echo "    # -- Enable Kubernetes liveness probe for Redis server"
    echo "    enabled: true"
    echo
    echo "  # -- Resource limits and requests for redis"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 100m"
    echo "      memory: 128Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo
    echo "  metrics:"
    echo "    # -- Deploy metrics service"
    echo "    enabled: true"
    echo
    echo "    # Redis metrics service configuration"
    echo "    service:"
    echo "      # -- Metrics service type"
    echo "      type: ClusterIP"
    echo "      # -- Metrics service clusterIP. 'None' makes a "headless service" (no virtual IP)"
    echo "      clusterIP: None"
    echo
    echo "    serviceMonitor:"
    echo "      # -- Enable a prometheus ServiceMonitor"
    echo "      enabled: true"
    echo "      # -- When true, honorLabels preserves the metric's labels when they collide with the target's labels."
    echo "      honorLabels: true"
    echo "      # -- Prometheus ServiceMonitor selector"
    echo "      selector: {}"
    echo "        # prometheus: kube-prometheus"
    echo "      # -- Prometheus ServiceMonitor namespace"
    echo "      namespace: \"\""
    echo
    echo "  # Default redis's network policy"
    echo "  networkPolicy:"
    echo "    # -- Default network policy rules used by redis"
    echo "    create: true"
    echo
    echo "redisSecretInit:"
    echo "  # -- Enable Redis secret initialization. If disabled, secret must be provisioned by alternative methods"
    echo "  enabled: true"
    echo
    echo "  # -- Resource limits and requests for Redis secret-init Job"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 100m"
    echo "      memory: 128Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 64Mi"
    echo
    echo "## Server"
    echo "server:"
    echo "  # -- The number of server pods to run"
    echo "  replicas: 3"
    echo
    echo "  ## Argo CD server Pod Disruption Budget"
    echo "  pdb:"
    echo "    # -- Deploy a [PodDisruptionBudget] for the Argo CD server"
    echo "    enabled: true"
    echo "    # -- Number of pods that are unavailable after eviction as number or percentage (eg.: 50%)."
    echo "    maxUnavailable: 1"
    echo
    echo "  ## Argo CD server emptyDir volumes"
    echo "  emptyDir:"
    echo "    # -- EmptyDir size limit for the Argo CD server"
    echo "    sizeLimit: 1Gi"
    echo
    echo "  # -- Resource limits and requests for the Argo CD server"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 100m"
    echo "      memory: 128Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 64Mi"
    echo
    echo "  # -- Deployment strategy to be added to the server Deployment"
    echo "  deploymentStrategy:"
    echo "    type: RollingUpdate"
    echo "    rollingUpdate:"
    echo "      maxSurge: 1"
    echo "      maxUnavailable: 1"
    echo
    echo "  ## Server metrics service configuration"
    echo "  metrics:"
    echo "    # -- Deploy metrics service"
    echo "    enabled: true"
    echo "    service:"
    echo "      # -- Metrics service type"
    echo "      type: ClusterIP"
    echo "      # -- Metrics service clusterIP. \`None\` makes a "headless service" (no virtual IP)"
    echo "      clusterIP: \"\""
    echo "    serviceMonitor:"
    echo "      # -- Enable a prometheus ServiceMonitor"
    echo "      enabled: true"
    echo "      # -- When true, honorLabels preserves the metric's labels when they collide with the target's labels."
    echo "      honorLabels: true"
    echo "      # -- Prometheus ServiceMonitor selector"
    echo "      selector: {}"
    echo "        # prometheus: kube-prometheus"
    echo "      # -- Prometheus ServiceMonitor namespace"
    echo "      namespace: \"\""
    echo
    echo "  # Default ArgoCD Server's network policy"
    echo "  networkPolicy:"
    echo "    # -- Default network policy rules used by ArgoCD Server"
    echo "    create: true"
    echo
    echo "## Repo Server"
    echo "repoServer:"
    echo "  # -- Repo server name"
    echo "  name: repo-server"
    echo
    echo "  # -- The number of repo server pods to run"
    echo "  replicas: 3"
    echo
    echo "  ## Repo server Pod Disruption Budget"
    echo "  ## Ref: https://kubernetes.io/docs/tasks/run-application/configure-pdb/"
    echo "  pdb:"
    echo "    # -- Deploy a [PodDisruptionBudget] for the repo server"
    echo "    enabled: true"
    echo "    # -- Number of pods that are unavailable after eviction as number or percentage (eg.: 50%)."
    echo "    maxUnavailable: 1"
    echo
    echo "  copyutil:"
    echo "    # -- Resource limits and requests for the repo server copyutil initContainer"
    echo "    resources:"
    echo "      limits:"
    echo "        cpu: 100m"
    echo "        memory: 128Mi"
    echo "      requests:"
    echo "        cpu: 50m"
    echo "        memory: 64Mi"
    echo
    echo "  ## RepoServer emptyDir volumes"
    echo "  emptyDir:"
    echo "    # -- EmptyDir size limit for repo server"
    echo "    sizeLimit: 1Gi"
    echo
    echo "  # -- Resource limits and requests for the repo server pods"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 50m"
    echo "      memory: 128Mi"
    echo "    requests:"
    echo "      cpu: 10m"
    echo "      memory: 64Mi"
    echo
    echo "  # -- Deployment strategy to be added to the repo server Deployment"
    echo "  deploymentStrategy:"
    echo "    type: RollingUpdate"
    echo "    rollingUpdate:"
    echo "      maxSurge: 1"
    echo "      maxUnavailable: 1"
    echo
    echo "  ## Repo server metrics service configuration"
    echo "  metrics:"
    echo "    # -- Deploy metrics service"
    echo "    enabled: true"
    echo "    service:"
    echo "      # -- Metrics service type"
    echo "      type: ClusterIP"
    echo "      # -- Metrics service clusterIP. \`None\` makes a "headless service" (no virtual IP)"
    echo "      clusterIP: \"\""
    echo "    serviceMonitor:"
    echo "      # -- Enable a prometheus ServiceMonitor"
    echo "      enabled: true"
    echo "      # -- When true, honorLabels preserves the metric's labels when they collide with the target's labels."
    echo "      honorLabels: true"
    echo "      # -- Prometheus ServiceMonitor selector"
    echo "      selector: {}"
    echo "        # prometheus: kube-prometheus"
    echo "      namespace: \"\""
    echo
    echo "  # Default repo server's network policy"
    echo "  networkPolicy:"
    echo "    # -- Default network policy rules used by repo server"
    echo "    create: true"
    echo
    echo "## ApplicationSet controller"
    echo "applicationSet:"
    echo
    echo "  # -- The number of ApplicationSet controller pods to run"
    echo "  replicas: 3"
    echo
    echo "  ## ApplicationSet controller Pod Disruption Budget"
    echo "  ## Ref: https://kubernetes.io/docs/tasks/run-application/configure-pdb/"
    echo "  pdb:"
    echo "    # -- Deploy a [PodDisruptionBudget] for the ApplicationSet controller"
    echo "    enabled: true"
    echo "    # -- Number of pods that are unavailable after eviction as number or percentage (eg.: 50%)."
    echo "    maxUnavailable: 1"
    echo
    echo "  ## ApplicationSet controller emptyDir volumes"
    echo "  emptyDir:"
    echo "    # -- EmptyDir size limit for applicationSet controller"
    echo "    sizeLimit: 1Gi"
    echo
    echo "  ## Metrics service configuration"
    echo "  metrics:"
    echo "    # -- Deploy metrics service"
    echo "    enabled: true"
    echo "    service:"
    echo "      # -- Metrics service type"
    echo "      type: ClusterIP"
    echo "      # -- Metrics service clusterIP. \`None\` makes a "headless service" (no virtual IP)"
    echo "      clusterIP: \"\""
    echo "    serviceMonitor:"
    echo "      # -- Enable a prometheus ServiceMonitor"
    echo "      enabled: true"
    echo "      # -- When true, honorLabels preserves the metric's labels when they collide with the target's labels."
    echo "      honorLabels: true"
    echo "      # -- Prometheus ServiceMonitor selector"
    echo "      selector: {}"
    echo "        # prometheus: kube-prometheus"
    echo "      # -- Prometheus ServiceMonitor namespace"
    echo "      namespace: \"\""
    echo
    echo "  # -- Resource limits and requests for the ApplicationSet controller pods."
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 100m"
    echo "      memory: 256Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 50Mi"
    echo
    echo "  ## Probes for ApplicationSet controller (optional)"
    echo "  readinessProbe:"
    echo "    # -- Enable Kubernetes liveness probe for ApplicationSet controller"
    echo "    enabled: true"
    echo
    echo "  livenessProbe:"
    echo "    # -- Enable Kubernetes liveness probe for ApplicationSet controller"
    echo "    enabled: true"
    echo
    echo "  # -- Deployment strategy to be added to the ApplicationSet controller Deployment"
    echo "  deploymentStrategy:"
    echo "    type: RollingUpdate"
    echo "    rollingUpdate:"
    echo "      maxSurge: 1"
    echo "      maxUnavailable: 1"
    echo
    echo "  # -- Enable ApplicationSet in any namespace feature"
    echo "  allowAnyNamespace: true"
    echo
    echo "  # Default ApplicationSet controller's network policy"
    echo "  networkPolicy:"
    echo "    # -- Default network policy rules used by ApplicationSet controller"
    echo "    create: true"
    echo
    echo "## Notifications controller"
    echo "notifications:"
    echo "  # -- Enable notifications controller"
    echo "  enabled: true"
    echo
    echo "  ## Notifications controller Pod Disruption Budget"
    echo "  ## Ref: https://kubernetes.io/docs/tasks/run-application/configure-pdb/"
    echo "  pdb:"
    echo "    # -- Deploy a [PodDisruptionBudget] for the notifications controller"
    echo "    enabled: true"
    echo "    # -- Number of pods that are unavailable after eviction as number or percentage (eg.: 50%)."
    echo "    maxUnavailable: 1"
    echo
    echo "  secret:"
    echo "    # -- Whether helm chart creates notifications controller secret"
    echo "    ## If true, will create a secret with the name below. Otherwise, will assume existence of a secret with that name."
    echo "    create: true"
    echo
    echo "    # -- Generic key:value pairs to be inserted into the secret"
    echo "    ## Can be used for templates, notification services etc. Some examples given below."
    echo "    ## For more information: https://argo-cd.readthedocs.io/en/stable/operator-manual/notifications/services/overview/"
    echo "    items: {}"
    echo
    echo "  metrics:"
    echo "    # -- Enables prometheus metrics server"
    echo "    enabled: true"
    echo "    service:"
    echo "      # -- Metrics service type"
    echo "      type: ClusterIP"
    echo "      # -- Metrics service clusterIP. \`None\` makes a "headless service" (no virtual IP)"
    echo "      clusterIP: \"\""
    echo "    serviceMonitor:"
    echo "      # -- Enable a prometheus ServiceMonitor"
    echo "      enabled: true"
    echo "      # -- Prometheus ServiceMonitor selector"
    echo "      selector: {}"
    echo "        # prometheus: kube-prometheus"
    echo "      # -- When true, honorLabels preserves the metric's labels when they collide with the target's labels."
    echo "      honorLabels: true"
    echo
    echo "  # -- Configures notification services such as slack, email or custom webhook"
    echo "  ## For more information: https://argo-cd.readthedocs.io/en/stable/operator-manual/notifications/services/overview/"
    echo "  notifiers: {}"
    echo
    echo "  # -- Resource limits and requests for the notifications controller"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 100m"
    echo "      memory: 128Mi"
    echo "    requests:"
    echo "      cpu: 50m"
    echo "      memory: 64Mi"
    echo
    echo "  ## Probes for notifications controller Pods (optional)"
    echo "  readinessProbe:"
    echo "    # -- Enable Kubernetes liveness probe for notifications controller Pods"
    echo "    enabled: true"
    echo "  livenessProbe:"
    echo "    # -- Enable Kubernetes liveness probe for notifications controller Pods"
    echo "    enabled: true"
    echo
    echo "  # -- The notification template is used to generate the notification content"
    echo "  ## For more information: https://argo-cd.readthedocs.io/en/stable/operator-manual/notifications/templates/"
    echo "  templates: {}"
    echo "  # -- The trigger defines the condition when the notification should be sent"
    echo "  ## For more information: https://argo-cd.readthedocs.io/en/stable/operator-manual/notifications/triggers/"
    echo "  triggers: {}"
    echo "  # Default notifications controller's network policy"
    echo "  networkPolicy:"
    echo "    # -- Default network policy rules used by notifications controller"
    echo "    create: true"
  } > "$ARGOCD_CONFIG_DIR/values.yaml"

  {
    echo "apiVersion: argoproj.io/v1alpha1"
    echo "kind: Application"
    echo "metadata:"
    echo "  name: bootstrap"
    echo "  namespace: argocd"
    echo "spec:"
    echo "  project: default"
    echo "  source:"
    echo "    repoURL: https://github.com/KubeMite/gitops.git"
    echo "    path: bootstrap"
    echo "  destination:"
    echo "    server: https://kubernetes.default.svc"
    echo "    namespace: argocd"
    echo "  syncPolicy:"
    echo "    automated:"
    echo "      prune: true"
    echo "      selfHeal: true"
    echo "    syncOptions:"
    echo "      - CreateNamespace=true"
  }> "$ARGOCD_CONFIG_DIR/root-app.yaml"

  # Download argocd images
  for image in $( { helm template argocd oci://ghcr.io/argoproj/argo-helm/argo-cd --values "$ARGOCD_CONFIG_DIR/values.yaml" --version "$ARGOCD_VERSION" 2>&1 1>&3 | grep -vE '^(Pulled:|Digest:)' >&2; } 3>&1 | grep 'image: ' | awk '{print $2}' | sort -u ); do
    nerdctl pull -q "$image"
  done
}

kubernetes_hardening() {
  chmod 600 -R /etc/kubernetes/thirdparty

  mkdir /var/log/kubernetes
  chmod 600 /var/log/kubernetes
}

main() {
  # Harden filesystems
  restrict_unused_filesystems
  harden_tmpfs
  harden_kernel_params

  # Harden networking
  restrict_uncommon_network_protocols
  harden_ipv4_kernel_params

  harden_crash_dumps_info

  connection_warning

  # APT
  apt_configuration

  # Users & Groups
  harden_user_group_folder_permissions
  sudo_hardening
  harden_login_session_options

  # SSH
  harden_ssh

  # Third-party utilities
  harden_cron
  harden_journald
  haveged
  auditd
  unattended_upgrades
  cloud_init
  setup_cosign

  # Kubernetes
  kubernetes_sysctl_networking
  sed -i '/\sswap\s/ s/^/#/' /etc/fstab # Disable swap
  install_cri
  install_kubernetes_utilities
  configure_ha
  install_cni
  prometheus_crd
  gatewayapi_crd
  cert_manager
  eso_bws
  argocd
  kubernetes_hardening
}

main