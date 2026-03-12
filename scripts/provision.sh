#!/bin/bash
#
# Configure hardened Kubernetes node golden image

# Set non-interactive frontend to prevent apt hangs
export DEBIAN_FRONTEND=noninteractive

# Disable filesystem drivers for unused filesystems, which decreases the attack surface
restrict_unused_filesystems() {
  local filesystem_blacklist_file="/etc/modprobe.d/fs-blacklist.conf"
  local filesystems_to_block=(ceph cifs cramfs exfat ext firewire-core \
  freevxfs fscache fuse gfs2 hfs hfsplus jffs2 smbfs_common \
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
    echo "    cpu: 500m"
    echo "    memory: 1Gi"
    echo "  requests:"
    echo "    cpu: 100m"
    echo "    memory: 512Mi"
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
    echo "      cpu: 100m"
    echo "      memory: 10Mi"
    echo "    limits:"
    echo "      cpu: 500m"
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
    echo "      cpu: 100m"
    echo "      memory: 100Mi"
    echo "    limits:"
    echo "      cpu: 500m"
    echo "      memory: 500Mi"
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
    echo "        cpu: 500m"
    echo "        memory: 500Mi"
    echo "      requests:"
    echo "        cpu: 100m"
    echo "        memory: 100Mi"
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
    echo "          cpu: 500m"
    echo "          memory: 300Mi"
    echo "        requests:"
    echo "          cpu: 100m"
    echo "          memory: 64Mi"
    echo "    frontend:"
    echo "      resources:"
    echo "        limits:"
    echo "          cpu: 500m"
    echo "          memory: 300Mi"
    echo "        requests:"
    echo "          cpu: 100m"
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
    echo "      cpu: 5000m"
    echo "      memory: 1Gi"
    echo "    requests:"
    echo "      cpu: 100m"
    echo "      memory: 200Mi"
    echo "  prometheus:"
    echo "    serviceMonitor:"
    echo "      enabled: true"
    echo
    echo "operator:"
    echo "  rollOutPods: true"
    echo "  resources:"
    echo "    limits:"
    echo "      cpu: 500m"
    echo "      memory: 500Mi"
    echo "    requests:"
    echo "      cpu: 100m"
    echo "      memory: 100Mi"
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
    echo "      cpu: 100m"
    echo "      memory: 128Mi"
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

# Install Longhorn CSI plugin
csi() {
  local CSI_VERSION
  local CSI_CONFIG_DIR

  CSI_VERSION="1.11.0"
  CSI_CONFIG_DIR="/etc/kubernetes/thirdparty/csi"

  mkdir -p "$CSI_CONFIG_DIR"

  # Setup values.yaml for helm chart
  {
    echo "global:"
    echo "  # -- Set container timezone (TZ env) for all Longhorn workloads. Leave empty to use container default."
    echo "  timezone: \"Asia/Jerusalem\""
    echo "networkPolicies:"
    echo "  # -- Setting that allows you to enable network policies that control access to Longhorn pods."
    echo "  enabled: true"
    echo "  # -- Distribution that determines the policy for allowing access for an ingress. (Options: \"k3s\", \"rke2\", \"rke1\")"
    echo "  type: \"k3s\""
    echo "image:"
    echo "  longhorn:"
    echo "    manager:"
    echo "      # -- Tag for the Longhorn Manager image."
    echo "      tag: v1.11.0-hotfix-1"
    echo "    instanceManager:"
    echo "      # -- Tag for the Longhorn Instance Manager image."
    echo "      tag: v1.11.0-hotfix-1"
    echo "service:"
    echo "  ui:"
    echo "    # -- Service type for Longhorn UI. (Options: \"ClusterIP\", \"NodePort\", \"LoadBalancer\", \"Rancher-Proxy\")"
    echo "    type: LoadBalancer"
    echo "  manager:"
    echo "    # -- Service type for Longhorn Manager."
    echo "    type: LoadBalancer"
    echo "persistence:"
    echo "  # -- VolumeBindingMode controls when volume binding and dynamic provisioning should occur. (Options: \"Immediate\", \"WaitForFirstConsumer\") (Defaults to \"Immediate\")"
    echo "  volumeBindingMode: \"WaitForFirstConsumer\""
    echo "  # -- Setting that allows you to enable live migration of a Longhorn volume from one node to another."
    echo "  migratable: true"
    echo "  # -- Setting that disables the revision counter and thereby prevents Longhorn from tracking all write operations to a volume. When salvaging a volume, Longhorn uses properties of the volume-head-xxx.img file (the last file size and the last time the file was modified) to select the replica to be used for volume recovery."
    echo "  disableRevisionCounter: \"false\""
    echo "  # -- Setting that allows you to enable automatic snapshot removal during filesystem trim for a Longhorn StorageClass. (Options: \"ignored\", \"enabled\", \"disabled\")"
    echo "  unmapMarkSnapChainRemoved: enabled"
    echo "preUpgradeChecker:"
    echo "  # -- Setting that allows Longhorn to perform upgrade version checks after starting the Longhorn Manager DaemonSet Pods. Disabling this setting also disables `preUpgradeChecker.jobEnabled`. Longhorn recommends keeping this setting enabled."
    echo "  upgradeVersionCheck: false"
    echo "defaultSettings:"
    echo "  # -- Setting that automatically rebalances replicas when an available node is discovered."
    echo "  replicaAutoBalance: least-effort"
    echo "  # -- Resource limits for system-managed CSI components."
    echo "  # This setting allows you to configure CPU and memory requests/limits for CSI attacher, provisioner, resizer, snapshotter, and plugin components."
    echo "  # Supported components: csi-attacher, csi-provisioner, csi-resizer, csi-snapshotter, longhorn-csi-plugin, node-driver-registrar, longhorn-liveness-probe."
    echo "  # Notice that changing resource limits will cause CSI components to restart, which may temporarily affect volume provisioning and attach/detach operations until the components are ready. The value should be a JSON object with component names as keys and ResourceRequirements as values."
    echo "  systemManagedCSIComponentsResourceLimits: >"
    echo "    {\"
    echo "      \"csi-attacher\": {\"
    echo "        \"requests\": {\"cpu\": \"100m\", \"memory\": \"128Mi\"},"
    echo "        \"limits\": {\"cpu\": \"200m\", \"memory\": \"256Mi\"}"
    echo "      },"
    echo "      \"csi-provisioner\": {"
    echo "        \"requests\": {\"cpu\": \"100m\", \"memory\": \"128Mi\"},"
    echo "        \"limits\": {\"cpu\": \"200m\", \"memory\": \"256Mi\"}"
    echo "      },"
    echo "      \"csi-resizer\": {"
    echo "        \"requests\": {\"cpu\": \"100m\", \"memory\": \"128Mi\"},"
    echo "        \"limits\": {\"cpu\": \"200m\", \"memory\": \"256Mi\"}"
    echo "      },"
    echo "      \"csi-snapshotter\": {"
    echo "        \"requests\": {\"cpu\": \"100m\", \"memory\": \"128Mi\"},"
    echo "        \"limits\": {\"cpu\": \"200m\", \"memory\": \"256Mi\"}"
    echo "      },"
    echo "      \"longhorn-csi-plugin\": {"
    echo "        \"requests\": {\"cpu\": \"100m\", \"memory\": \"128Mi\"},"
    echo "        \"limits\": {\"cpu\": \"200m\", \"memory\": \"256Mi\"}"
    echo "      },"
    echo "      \"node-driver-registrar\": {"
    echo "        \"requests\": {\"cpu\": \"50m\", \"memory\": \"64Mi\"},"
    echo "        \"limits\": {\"cpu\": \"100m\", \"memory\": \"128Mi\"}"
    echo "      },"
    echo "      \"longhorn-liveness-probe\": {"
    echo "        \"requests\": {\"cpu\": \"50m\", \"memory\": \"64Mi\"},"
    echo "        \"limits\": {\"cpu\": \"100m\", \"memory\": \"128Mi\"}"
    echo "      }"
    echo "    }"
    echo "  # -- Setting that allows scheduling on disks with existing healthy replicas of the same volume. This setting is enabled by default."
    echo "  replicaDiskSoftAntiAffinity: false"
    echo "  # -- Setting that allows disabling of snapshot hashing after snapshot creation to minimize impact on system performance."
    echo "  snapshotDataIntegrityImmediateCheckAfterSnapshotCreation: false"
    echo "  # -- Setting that allows Longhorn to periodically collect anonymous usage data for product improvement purposes. Longhorn sends collected data to the [Upgrade Responder](https://github.com/longhorn/upgrade-responder) server, which is the data source of the Longhorn Public Metrics Dashboard (https://metrics.longhorn.io). The Upgrade Responder server does not store data that can be used to identify clients, including IP addresses."
    echo "  allowCollectingLonghornUsageMetrics: false"
    echo "  # -- Setting that automatically cleans up the snapshot when the backup is deleted."
    echo "  autoCleanupSnapshotWhenDeleteBackup: true"
    echo "  # -- Setting that automatically cleans up the snapshot after the on-demand backup is completed."
    echo "  autoCleanupSnapshotAfterOnDemandBackupCompleted: true"
    echo "  # -- Controls whether Longhorn monitors and records health information for node disks. When disabled, disk health checks and status updates are skipped."
    echo "  nodeDiskHealthMonitoring: true"
    echo "longhornManager:"
    echo "  # -- Resource requests and limits for Longhorn Manager pods."
    echo "  resources:"
    echo "    requests:"
    echo "      cpu: 100m"
    echo "      memory: 128Mi"
    echo "    limits:"
    echo "      cpu: 200m"
    echo "      memory: 256Mi"
    echo "enablePSP: true"
    echo "metrics:"
    echo "  serviceMonitor:"
    echo "    # -- Setting that allows the creation of a Prometheus ServiceMonitor resource for Longhorn Manager components."
    echo "    enabled: true"
  } > "$CSI_CONFIG_DIR/values.yaml"

  # Prerequisites
  systemctl enable iscsid
  helm repo add longhorn https://charts.longhorn.io
  helm repo update

  for image in $(curl -fsSL https://github.com/longhorn/longhorn/releases/download/v1.11.0/longhorn-images.txt); do
    nerdctl pull -q "$image"
  done
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
  csi
}

main