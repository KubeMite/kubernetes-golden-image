#!/bin/bash

#TODO: Make this install kubernetes

# Restrict unused filesystem drivers
cat <<EOF > /etc/modprobe.d/fs-blacklist.conf
blacklist ceph
install ceph /bin/false
blacklist cifs
install cifs /bin/false
blacklist cramfs
install cramfs /bin/false
blacklist exfat
install exfat /bin/false
blacklist ext
install ext /bin/false
blacklist firewire-core
install firewire-core /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist fscache
install fscache /bin/false
blacklist fuse
install fuse /bin/false
blacklist gfs2
install gfs2 /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist nfs_common
install nfs_common /bin/false
blacklist nfsd
install nfsd /bin/false
blacklist smbfs_common
install smbfs_common /bin/false
blacklist squashfs
install squashfs /bin/false
blacklist udf
install udf /bin/false
blacklist usb_storage
install usb_storage /bin/false
EOF

# Mount /tmp as hardened tmpfs
echo 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,mode=1777 0 0' >> /etc/fstab
# Mount /dev/shm as hardened tmpfs
echo 'tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,size=1024M,mode=1777 0 0' >> /etc/fstab

# Harden kernel parameters
cat <<EOF >/etc/sysctl.d/kernel-hardening.conf
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
dev.tty.ldisc_autoload = 0
fs.protected_fifos = 2
fs.protected_regular = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.core_pattern = |/bin/false
kernel.perf_event_paranoid = 3
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
net.core.bpf_jit_harden = 2
EOF

# Harden networking
## Disable uncommon protocols and kernal modules as these may have unknown vulnerabilties
cat <<EOF > /etc/modprobe.d/blacklist-uncommon-networking.conf
blacklist atm
install atm /bin/false
blacklist can
install can /bin/false
blacklist dccp
install dccp /bin/false
blacklist rds
install rds /bin/false
blacklist sctp
install sctp /bin/false
blacklist tipc
install tipc /bin/false
EOF
## Harden IPv4 kernel parameters
cat <<EOF > /etc/sysctl.d/ipv4-hardening.conf
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
EOF

# Harden core dumps & Crash logs
echo '* hard core 0' >> /etc/security/limits.conf
echo '* soft core 0' >> /etc/security/limits.conf

# Ensure root password is required in rescue and emergency mode
sed -i 's/ExecStart=-\/lib\/systemd\/systemd-sulogin-shell emergency/ExecStart=-\/bin\/sh -c "\/usr\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default"/g' /usr/lib/systemd/system/emergency.service
sed -i 's/ExecStart=-\/lib\/systemd\/systemd-sulogin-shell rescue/ExecStart=-\/bin\/sh -c "\/usr\/sbin\/sulogin; \/usr\/bin\/systemctl --fail --no-block default"/g' /usr/lib/systemd/system/rescue.service

# Connection warning about unauthorized access
for item in /etc/issue /etc/issue.net /etc/motd; do
    cat <<EOF > "$item"
UNAUTHORIZED ACCESS TO THIS DEVICE IS PROHIBITED
  You must have explicit, authorized permission to access or configure this device.
  Unauthorized attempts and actions to access or use this system may result in civil and/or criminal penalties.
  All activities performed on this device are logged and monitored.

EOF
done

# Users & Groups
## Harden folder permissions
chmod 0000 /etc/gshadow
chown root:root /etc/gshadow
chown root:root /etc/group
chmod 0644 /etc/passwd
chown root:root /etc/passwd
chmod 0640 /etc/shadow
chown root:root /etc/shadow
## Sudo hardening
### Harden sudo config folder access
chmod 750 /etc/sudoers.d
### Disable su access (sudo logging is more verbose)
groupadd sugroup
echo "auth required pam_wheel.so use_uid group=sugroup" > /etc/pam.d/su
### Log sudo command access
echo 'Defaults	logfile="/var/log/sudo.log"' > /etc/sudoers.d/01_sudo_hardening
chmod o-r,g-r /etc/sudoers.d/01_sudo_hardening
## Harden login options
printf 'session optional pam_umask.so\n' >> /etc/pam.d/common-session
echo "UMASK 027" >> /etc/login.defs
echo "UID_MIN 1000" >> /etc/login.defs
## Set terminal timeout
printf 'TMOUT=300\n' >> /home/user/.bashrc
printf 'TMOUT=300\n' >> /root/.bashrc
## Allow root to login only from physical terminals
cat <<EOF > /etc/securetty
tty1
tty2
tty3
tty4
tty5
tty6
EOF
## Fix folders in path
echo "export PATH=$PATH:/sbin:/usr/sbin" >> /root/.bashrc

# SSH
## SSHD hardening options
cat <<EOF > /etc/ssh/sshd_config.d/hardening.conf
# Cryptography
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768x25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

# Authentication & Access Control
AllowUsers user
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 60
HostbasedAuthentication no
IgnoreRhosts yes

# Session & Connection Management
MaxSessions 2
MaxStartups 10:30:60
TCPKeepAlive no
ClientAliveInterval 150
ClientAliveCountMax 2
Compression no

# Restriction & Forwarding
DisableForwarding yes
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitUserEnvironment no

# Logging & UI
Banner /etc/issue
LogLevel VERBOSE
EOF
# Setup SSH key authentication
mkdir -p /home/user/.ssh
touch /home/user/.ssh/authorized_keys
## SSH folder permissions
chmod 600 /etc/ssh/sshd_config
chmod -R 600 /etc/ssh/sshd_config.d
chown -R user:user /home/user/.ssh
chmod 700 /home/user/.ssh
chmod 600 /home/user/.ssh/authorized_keys
## Restart SSH services to apply changes
systemctl restart ssh
systemctl restart sshd

# Apt configuration
## Ensure apt uses the debian keyring
sed -i 's|^deb |deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] |' /etc/apt/sources.list
sed -i 's|^deb-src |deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] |' /etc/apt/sources.list
## Ensure weak dependencies are not downloaded and installed
cat <<EOF > /etc/apt/apt.conf.d/60-no-weak-dependencies
APT::Install-Recommends "0";
APT::Install-Suggests "0";
EOF
## Ensure downloading packages uses https
sed -i 's/http/https/g' /etc/apt/sources.list

# Third-party utilities
## Harden cron
chmod 600 /etc/crontab
chown root:root /etc/crontab
chmod 700 /etc/cron.d
chown root:root /etc/cron.d
chmod 700 /etc/cron.daily
chown root:root /etc/cron.daily
chmod 700 /etc/cron.hourly
chown root:root /etc/cron.hourly
chmod 700 /etc/cron.weekly
chown root:root /etc/cron.weekly
chmod 700 /etc/cron.monthly
chown root:root /etc/cron.monthly
chmod 700 /etc/cron.yearly
chown root:root /etc/cron.yearly
echo root > /etc/cron.allow
chmod 600 /etc/cron.allow
chown root:root /etc/cron.allow
## Journald log rotation
sed -i 's/#Compress=yes/Compress=yes/g' /etc/systemd/journald.conf
sed -i 's/#ForwardToSyslog=no/ForwardToSyslog=no/g' /etc/systemd/journald.conf
sed -i 's/#MaxFileSec=1month/MaxFileSec=1month/g' /etc/systemd/journald.conf
sed -i 's/#RuntimeKeepFree=/RuntimeKeepFree=50M/g' /etc/systemd/journald.conf
sed -i 's/#RuntimeMaxUse=/RuntimeMaxUse=200M/g' /etc/systemd/journald.conf
sed -i 's/#Storage=auto/Storage=persistent/g' /etc/systemd/journald.conf
sed -i 's/#SystemKeepFree=/SystemKeepFree=500M/g' /etc/systemd/journald.conf
sed -i 's/#SystemMaxUse=/SystemMaxUse=1G/g' /etc/systemd/journald.conf
sed -i 's/ForwardToSyslog=yes/ForwardToSyslog=no/g' /usr/lib/systemd/journald.conf.d/syslog.conf
systemctl reload-or-restart systemd-journald
## Haveged to improve entropy
systemctl enable --now haveged
printf '/usr/local/sbin/haveged -w 1024' > /etc/rc.local
## AuditD
### Configuration
sed -i 's/^admin_space_left_action.*/admin_space_left_action = rotate/' /etc/audit/auditd.conf
sed -i 's/^disk_error_action.*/disk_error_action = syslog/' /etc/audit/auditd.conf
sed -i 's/^disk_full_action.*/disk_full_action = rotate/' /etc/audit/auditd.conf
sed -i 's/^max_log_file.*/max_log_file = 5/' /etc/audit/auditd.conf
sed -i 's/^space_left_action.*/space_left_action = rotate/' /etc/audit/auditd.conf
### Rules
echo "-c" >> /etc/audit/rules.d/01-initialize.rules
cat <<EOF > /etc/audit/rules.d/50-scope.rules
-a always,exit -F arch=b32 -S all -F path=/etc/sudoers -F perm=wa -k scope
-a always,exit -F arch=b64 -S all -F path=/etc/sudoers -F perm=wa -k scope
-a always,exit -F arch=b32 -S all -F dir=/etc/sudoers.d -F perm=wa -k scope
-a always,exit -F arch=b64 -S all -F dir=/etc/sudoers.d -F perm=wa -k scope
EOF
cat <<EOF > /etc/audit/rules.d/50-user_emulation.rules
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
EOF
cat <<EOF > /etc/audit/rules.d/50-sudo.rules
-a always,exit -F arch=b32 -S all -F path=/var/log/sudo.log -F perm=wa -k sudo_log_file
-a always,exit -F arch=b64 -S all -F path=/var/log/sudo.log -F perm=wa -k sudo_log_file
EOF
cat <<EOF > /etc/audit/rules.d/50-time-change.rules
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
EOF
cat <<EOF > /etc/audit/rules.d/50-local-time-change.rules
-a always,exit -F arch=b32 -S all -F path=/etc/localtime -F perm=wa -k localtime-change
-a always,exit -F arch=b64 -S all -F path=/etc/localtime -F perm=wa -k localtime-change
EOF
cat <<EOF > /etc/audit/rules.d/50-system_locale.rules
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
EOF
cat <<EOF > /etc/audit/rules.d/50-etc_issue_system_locale.rules
-a always,exit -F arch=b32 -S all -F path=/etc/issue -F perm=wa -k system-locale
-a always,exit -F arch=b64 -S all -F path=/etc/issue -F perm=wa -k system-locale
-a always,exit -F arch=b32 -S all -F path=/etc/issue.net -F perm=wa -k system-locale
-a always,exit -F arch=b64 -S all -F path=/etc/issue.net -F perm=wa -k system-locale
EOF
cat <<EOF > /etc/audit/rules.d/50-etc_host_system_locale.rules
-a always,exit -F arch=b32 -S all -F path=/etc/hosts -F perm=wa -k system-locale
-a always,exit -F arch=b64 -S all -F path=/etc/hosts -F perm=wa -k system-locale
-a always,exit -F arch=b32 -S all -F path=/etc/hostname -F perm=wa -k system-locale
-a always,exit -F arch=b64 -S all -F path=/etc/hostname -F perm=wa -k system-locale
EOF
cat <<EOF > /etc/audit/rules.d/50-etc_sysconfig_system_locale.rules
-a always,exit -F arch=b32 -S all -F path=/etc/network/interfaces -F perm=wa -k system-locale
-a always,exit -F arch=b64 -S all -F path=/etc/network/interfaces -F perm=wa -k system-locale
-a always,exit -F arch=b32 -S all -F dir=/etc/network/interfaces.d -F perm=wa -k system-locale
-a always,exit -F arch=b64 -S all -F dir=/etc/network/interfaces.d -F perm=wa -k system-locale
EOF
cat <<EOF > /etc/audit/rules.d/50-access.rules
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
EOF
cat <<EOF > /etc/audit/rules.d/50-identity.rules
-a always,exit -F arch=b32 -S all -F path=/etc/group -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F path=/etc/group -F perm=wa -k identity
-a always,exit -F arch=b32 -S all -F path=/etc/passwd -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=wa -k identity
-a always,exit -F arch=b32 -S all -F path=/etc/gshadow -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F path=/etc/gshadow -F perm=wa -k identity
-a always,exit -F arch=b32 -S all -F path=/etc/shadow -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F path=/etc/shadow -F perm=wa -k identity
-a always,exit -F arch=b32 -S all -F path=/etc/security/opasswd -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F path=/etc/security/opasswd -F perm=wa -k identity
-a always,exit -F arch=b32 -S all -F path=/etc/nsswitch.conf -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F path=/etc/nsswitch.conf -F perm=wa -k identity
-a always,exit -F arch=b32 -S all -F path=/etc/pam.conf -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F path=/etc/pam.conf -F perm=wa -k identity
-a always,exit -F arch=b32 -S all -F dir=/etc/pam.d -F perm=wa -k identity
-a always,exit -F arch=b64 -S all -F dir=/etc/pam.d -F perm=wa -k identity
EOF
cat <<EOF > /etc/audit/rules.d/50-perm_mod.rules
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
EOF
cat <<EOF > /etc/audit/rules.d/50-mounts.rules
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
EOF
cat <<EOF > /etc/audit/rules.d/50-session.rules
-a always,exit -F arch=b32 -S all -F path=/var/run/utmp -F perm=wa -k session
-a always,exit -F arch=b64 -S all -F path=/var/run/utmp -F perm=wa -k session
-a always,exit -F arch=b32 -S all -F path=/var/log/wtmp -F perm=wa -k session
-a always,exit -F arch=b64 -S all -F path=/var/log/wtmp -F perm=wa -k session
-a always,exit -F arch=b32 -S all -F path=/var/log/btmp -F perm=wa -k session
-a always,exit -F arch=b64 -S all -F path=/var/log/btmp -F perm=wa -k session
EOF
cat <<EOF > /etc/audit/rules.d/50-login.rules
-a always,exit -F arch=b32 -S all -F path=/var/log/lastlog -F perm=wa -k logins
-a always,exit -F arch=b64 -S all -F path=/var/log/lastlog -F perm=wa -k logins
-a always,exit -F arch=b32 -S all -F path=/var/run/faillock -F perm=wa -k logins
-a always,exit -F arch=b64 -S all -F path=/var/run/faillock -F perm=wa -k logins
EOF
cat <<EOF > /etc/audit/rules.d/50-delete.rules
-a always,exit -F arch=b32 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S unlink,unlinkat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b32 -S rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S rename,renameat,renameat2 -F auid>=1000 -F auid!=unset -k delete
EOF
cat <<EOF > /etc/audit/rules.d/50-MAC-policy.rules
-a always,exit -F arch=b32 -S all -F path=/etc/apparmor -F perm=wa -k MAC-policy
-a always,exit -F arch=b64 -S all -F path=/etc/apparmor -F perm=wa -k MAC-policy
-a always,exit -F arch=b32 -S all -F dir=/etc/apparmor.d -F perm=wa -k MAC-policy
-a always,exit -F arch=b64 -S all -F dir=/etc/apparmor.d -F perm=wa -k MAC-policy
EOF
cat <<EOF > /etc/audit/rules.d/50-perm_chng.rules
-a always,exit -F arch=b32 -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F arch=b64 -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F arch=b32 -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F arch=b64 -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F arch=b32 -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
-a always,exit -F arch=b64 -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
EOF
cat <<EOF > /etc/audit/rules.d/50-usermod.rules
-a always,exit -F arch=b32 -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod
-a always,exit -F arch=b64 -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod
EOF
cat <<EOF > /etc/audit/rules.d/50-kernel_modules.rules
-a always,exit -F arch=b32 -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b64 -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b32 -S query_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F arch=b64 -S query_module -F auid>=1000 -F auid!=unset -k kernel_modules
EOF
echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules
augenrules --load
## Unattended upgrades
cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat <<EOF > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian";
    "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
systemctl enable --now unattended-upgrades
systemctl restart unattended-upgrades

# Set sysctl networking for kubernetes
cat <<EOF > /etc/sysctl.d/k8s.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding=1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

# Apply sysctl configuration
sysctl --system

# Cleanup
apt clean
