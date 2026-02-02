variable "proxmox_api_url" {
  type        = string
  description = "https://<proxmox-ip>:8006/api2/json"
}

variable "proxmox_api_token_id" {
  type        = string
  sensitive   = true
  description = "Token ID of API token for Proxmox authentication, e.g. <username>@pam!<token-name>"
}

variable "proxmox_api_token_secret" {
  type        = string
  sensitive   = true
  description = "Token secret of API token for Proxmox authentication"
}

variable "proxmox_node" {
  type        = string
  sensitive   = true
  description = "Proxmox node the vm will be created in"
}

variable "template_name" {
  type        = string
  sensitive   = false
  description = "The name of the vm template after the vm is configured"
}

variable "template_description" {
  type        = string
  sensitive   = false
  description = "The description of the vm template after the vm is configured"
}

variable "boot_iso" {
  type        = string
  sensitive   = true
  description = "The name of the local ISO the vm will boot from. e.g. debian-12.11.5-amd64-DVD-1.iso"
}

variable "boot_iso_checksum_path" {
  type        = string
  sensitive   = true
  description = "https://<iso checksum file URL>"
}

variable "vlan_tag" {
  type        = number
  sensitive   = true
  description = "VLAN tag of the VM network interface"
}

variable "ip" {
  type        = string
  sensitive   = true
  description = "The initial IP that will be set in the VM"
}

variable "netmask" {
  type        = string
  sensitive   = true
  description = "The initial netmask that will be set in the VM"
}

variable "gateway" {
  type        = string
  sensitive   = true
  description = "The initial gateway that will be set in the VM"
}

variable "dns_server" {
  type        = string
  sensitive   = true
  description = "The initial dns server that will be set in the VM"
}

variable "domain" {
  type        = string
  sensitive   = true
  description = "The initial domain that will be set in the VM"
}

variable "hostname" {
  type        = string
  sensitive   = true
  description = "The initial hostname that will be set in the VM"
}

variable "root_password" {
  type        = string
  sensitive   = true
  description = "Root user password"
}

variable "user_username" {
  type        = string
  sensitive   = false
  description = "Username of vm default user"
}

variable "user_password" {
  type        = string
  default     = env("USER_PASSWORD")
  sensitive   = true
  description = "Password of vm default user"
}

variable "timezone" {
  type        = string
  sensitive   = false
  description = "Timezone of the vm, e.g. Europe/Madrid"
  default     = "Asia/Jerusalem"
}

variable "ntp_servers" {
  type        = string
  sensitive   = false
  description = "NTP server(s) of the vm, e.g. 0.debian.pool.ntp.org"
  default     = "0.debian.pool.ntp.org"
}

variable "disk_size" {
  type        = string
  sensitive   = false
  description = "Disk size for vm, e.g. 30G"
  default     = "100G"
}

variable "storage_swap_size_mb" {
  type        = number
  sensitive   = false
  description = "Swap size in mb, e.g. 4096"
  default     = 1024
}

variable "storage_var_tmp_size_mb" {
  type        = number
  sensitive   = false
  description = "/var/tmp size in mb, e.g. 8192"
  default     = 5120
}

variable "storage_home_size_mb" {
  type        = number
  sensitive   = false
  description = "/home size in mb, e.g. 24576"
  default     = 10240
}

variable "storage_var_log_audit_size_mb" {
  type        = number
  sensitive   = false
  description = "/var/log/audit size in mb, e.g. 8192"
  default     = 5120
}

variable "storage_var_log_size_mb" {
  type        = number
  sensitive   = false
  description = "/var/log size in mb, e.g. 16384"
  default     = 10240
}

variable "storage_var_size_mb" {
  type        = number
  sensitive   = false
  description = "/var size in mb, e.g. 16384"
  default     = 15360
}

variable "memory_maximum" {
  type        = number
  sensitive   = false
  description = "In mb, vm will baloon to this size. e.g. 8192"
  default     = 4096
}

variable "memory_minimum" {
  type        = number
  sensitive   = false
  description = "In mb, vm will be try to be in this size. e.g. 4096"
  default     = 2048
}

variable "cpu_cores" {
  type        = number
  sensitive   = false
  description = "vm cpu cores, e.g. 2"
  default     = 2
}

variable "cpu_sockets" {
  type        = number
  sensitive   = false
  description = "vm cpu sockets, e.g. 1"
  default     = 1
}

variable "packages_to_install" {
  type        = string
  sensitive   = false
  description = "Apt packages that will be installed in the vm, e.g. man htop"
  default     = "man sudo htop openssh-server ncdu vim curl wget iptables iptables-persistent tcpdump dnsutils net-tools traceroute needrestart libpam-tmpdir apt-listchanges bash-completion qemu-guest-agent systemd-timesyncd auditd audispd-plugins unattended-upgrades haveged apt-listbugs cloud-init"
}

variable "ssh_port" {
  type        = number
  sensitive   = false
  description = "SSH port to access the vm"
  default     = 22
}

