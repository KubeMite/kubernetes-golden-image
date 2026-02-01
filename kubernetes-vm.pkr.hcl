packer {
  required_plugins {
    proxmox = {
      version = "~> 1"
      source  = "github.com/hashicorp/proxmox"
    }
  }
}

source "proxmox-iso" "vm" {

  # Proxmox Connection Settings
  proxmox_url = "${var.proxmox_api_url}"
  username    = "${var.proxmox_api_token_id}"
  token       = "${var.proxmox_api_token_secret}"
  # Skip TLS Verification
  insecure_skip_tls_verify = true

  # ISO location & verification
  boot_iso {
    type             = "scsi"
    iso_file         = "local:iso/${var.boot_iso}"
    unmount          = true
    iso_checksum     = "file:${var.boot_iso_checksum_path}"
    iso_storage_pool = "local"
    index            = "0"
  }
  additional_iso_files {
    type             = "scsi"
    unmount          = true
    iso_storage_pool = "local"
    cd_label         = "PRESEED"
    index            = "1"

    cd_content = {
      "preseed.cfg" = templatefile("${path.root}/http/preseed.cfg.pkrtpl", {
        ip                            = "${var.ip}"
        netmask                       = "${var.netmask}"
        gateway                       = "${var.gateway}"
        dns_server                    = "${var.dns_server}"
        domain                        = "${var.domain}"
        hostname                      = "${var.hostname}"
        root_password                 = "${var.root_password}"
        user_username                 = "${var.user_username}"
        user_password                 = "${var.user_password}"
        timezone                      = "${var.timezone}"
        ntp_servers                   = "${var.ntp_servers}"
        storage_swap_size_mb          = "${var.storage_swap_size_mb}"
        storage_var_tmp_size_mb       = "${var.storage_var_tmp_size_mb}"
        storage_home_size_mb          = "${var.storage_home_size_mb}"
        storage_var_log_audit_size_mb = "${var.storage_var_log_audit_size_mb}"
        storage_var_log_size_mb       = "${var.storage_var_log_size_mb}"
        storage_var_size_mb           = "${var.storage_var_size_mb}"
        packages_to_install           = "${var.packages_to_install}"
      })
    }
  }

  # VM hardware
  network_adapters {
    bridge   = "vmbr0"
    model    = "virtio"
    vlan_tag = "${var.vlan_tag}"
    firewall = true
  }
  disks {
    type         = "scsi"
    disk_size    = "${var.disk_size}"
    storage_pool = "local-lvm"
    cache_mode   = "none"
    format       = "raw"
  }
  memory             = "${var.memory_maximum}"
  ballooning_minimum = 0
  cores              = "${var.cpu_cores}"
  cpu_type           = "host"
  sockets            = "${var.cpu_sockets}"
  os                 = "l26"
  bios               = "seabios"
  qemu_agent         = true
  onboot             = true
  disable_kvm        = false

  # VM location & name
  node                 = "${var.proxmox_node}"
  template_name        = "${var.template_name}"
  template_description = "${var.template_description}"

  # Boot configuration
  boot         = "${var.boot_order}"
  boot_wait    = "${var.boot_wait}"
  boot_command = "${var.boot_command}"

  ssh_username           = "${var.user_username}"
  ssh_password           = "${var.user_password}"
  ssh_port               = "${var.ssh_port}"
  ssh_timeout            = "24h"
  ssh_pty                = true
  ssh_handshake_attempts = 20
}

build {
  sources = ["source.proxmox-iso.vm"]

  provisioner "shell" {
    # Run script as root
    execute_command = "echo ${var.user_password} | sudo -S {{.Vars}} bash {{.Path}}"
    environment_vars = [
      "SSH_PUBKEY=${var.ssh_pub_key}"
    ]
    script = "scripts/provision.sh"
  }

  post-processor "manifest" {
    output = "output/manifest.json"
  }

  # Setting template with balooning device post-setup (debian install is unstable on ballooning device)
  post-processor "shell-local" {
    environment_vars = [
      "PVE_URL=${var.proxmox_api_url}",
      "PVE_TOKEN=${var.proxmox_api_token_id}=${var.proxmox_api_token_secret}",
      "NODE=${var.proxmox_node}",
      "MEMORY_MAXIMUM=${var.memory_maximum}",
      "MEMORY_MINIMUM=${var.memory_minimum}"
    ]
    inline = [
      "VM_ID=$(jq -r '.builds[-1].artifact_id' output/manifest.json)",
      "curl -k -X POST \"$PVE_URL/nodes/$NODE/qemu/$VM_ID/config\" \\",
      "     -H \"Authorization: PVEAPIToken=$PVE_TOKEN\" \\",
      "     --data \"memory=$MEMORY_MAXIMUM&balloon=$MEMORY_MINIMUM\""
    ]
  }
}