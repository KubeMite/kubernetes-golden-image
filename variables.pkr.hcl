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
}

variable "ntp_servers" {
  type        = string
  sensitive   = false
  description = "NTP server(s) of the vm, e.g. 0.debian.pool.ntp.org"
}

variable "disk_size" {
  type        = string
  sensitive   = false
  description = "Disk size for vm, e.g. 30G"
}

variable "storage_swap_size_mb" {
  type        = number
  sensitive   = false
  description = "Swap size in mb, e.g. 4096"
}

variable "storage_var_tmp_size_mb" {
  type        = number
  sensitive   = false
  description = "/var/tmp size in mb, e.g. 8192"
}

variable "storage_home_size_mb" {
  type        = number
  sensitive   = false
  description = "/home size in mb, e.g. 24576"
}

variable "storage_var_log_audit_size_mb" {
  type        = number
  sensitive   = false
  description = "/var/log/audit size in mb, e.g. 8192"
}

variable "storage_var_log_size_mb" {
  type        = number
  sensitive   = false
  description = "/var/log size in mb, e.g. 16384"
}

variable "storage_var_size_mb" {
  type        = number
  sensitive   = false
  description = "/var size in mb, e.g. 16384"
}

variable "memory_maximum" {
  type        = number
  sensitive   = false
  description = "In mb, vm will baloon to this size. e.g. 8192"
}

variable "memory_minimum" {
  type        = number
  sensitive   = false
  description = "In mb, vm will be try to be in this size. e.g. 4096"
}

variable "cpu_cores" {
  type        = number
  sensitive   = false
  description = "vm cpu cores, e.g. 2"
}

variable "cpu_sockets" {
  type        = number
  sensitive   = false
  description = "vm cpu sockets, e.g. 1"
}

variable "boot_order" {
  type        = string
  sensitive   = false
  description = "vm will try to boot from devices in this order, e.g. order=scsi0;ide1;net0"
}

variable "boot_wait" {
  type        = string
  sensitive   = false
  description = "The amount of time Packer will wait before entering the boot command"
}

variable "boot_command" {
  type        = list(string)
  sensitive   = false
  description = "Packer will run these commands on initial vm boot"
}

variable "packages_to_install" {
  type        = string
  sensitive   = true
  description = "Apt packages that will be installed in the vm, e.g. man htop"
}

variable "ssh_pub_key" {
  type        = string
  sensitive   = true
  description = "SSH public key to access the vm"
}

variable "ssh_port" {
  type        = number
  sensitive   = true
  description = "SSH port to access the vm"
}

