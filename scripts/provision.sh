#!/bin/bash
#
# Configure hardened Kubernetes node golden image

# TODO: Install CNI (cilium) and CSI (to be decided)
# TODO: Maybe install cilium using helm as a startup command on one of the nodes?

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
    echo "  script "/etc/keepalived/check_apiserver.sh""
    echo "  interval 2"
    echo "  weight 10"
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
    echo "  @host01 priority 105"
    echo "  @host02 priority 100"
    echo "  @host03 priority 95"
    echo
    echo "  authentication {"
    echo "    auth_type PASS"
    echo "    auth_pass k8s-ha"
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

  # Kubernetes
  kubernetes_sysctl_networking
  sed -i '/\sswap\s/ s/^/#/' /etc/fstab # Disable swap
  install_cri
  install_kubernetes_utilities
  configure_ha
}

main