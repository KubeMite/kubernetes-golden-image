packer {
  required_plugins {
    proxmox = {
      version = "~> 1"
      source  = "github.com/hashicorp/proxmox"
    }
    external = {
      version = "> 0.0.2"
      source  = "github.com/joomcode/external"
    }
  }
}

data "external" "bws_secrets" {
  program = ["bash", "./scripts/get_bws_secrets.sh"]
  query = {
    access_token = var.bws_token
    project_id   = var.bws_project_id
  }
}

locals {
  bws_secrets = data.external.bws_secrets.result
}

source "proxmox-iso" "vm" {

  # Proxmox Connection Settings
  proxmox_url = "${local.bws_secrets["proxmox-api-endpoint"]}/api2/json"
  username    = local.bws_secrets["proxmox-root-api-token-id"]
  token       = local.bws_secrets["proxmox-root-api-token-secret"]
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
        ip                            = var.ip
        netmask                       = var.netmask
        gateway                       = var.gateway
        dns_server                    = var.dns_server
        domain                        = var.domain
        hostname                      = var.hostname
        root_password                 = "${local.bws_secrets["vm-template-root-password"]}"
        user_username                 = var.user_username
        user_password                 = "${local.bws_secrets["vm-template-user-password"]}"
        timezone                      = var.timezone
        ntp_servers                   = var.ntp_servers
        storage_swap_size_mb          = var.storage_swap_size_mb
        storage_var_tmp_size_mb       = var.storage_var_tmp_size_mb
        storage_home_size_mb          = var.storage_home_size_mb
        storage_var_log_audit_size_mb = var.storage_var_log_audit_size_mb
        storage_var_log_size_mb       = var.storage_var_log_size_mb
        storage_var_size_mb           = var.storage_var_size_mb
        packages_to_install           = var.packages_to_install
      })
    }
  }

  # Cloud-init
  cloud_init              = true
  cloud_init_storage_pool = "local-lvm"
  cloud_init_disk_type    = "ide"

  # VM hardware
  network_adapters {
    bridge   = "vmbr0"
    model    = "virtio"
    vlan_tag = var.vlan_tag
    firewall = true
  }
  disks {
    type         = "scsi"
    disk_size    = var.disk_size
    storage_pool = "local-lvm"
    cache_mode   = "none"
    format       = "raw"
  }
  memory             = var.memory_maximum
  ballooning_minimum = 0
  cores              = var.cpu_cores
  cpu_type           = "host"
  sockets            = var.cpu_sockets
  os                 = "l26"
  bios               = "seabios"
  qemu_agent         = true
  onboot             = true
  disable_kvm        = false

  # RNG from host to VM (otherwise all VMs will have similar randomness seeds)
  rng0 {
    source    = "/dev/urandom"
    max_bytes = 1024
    period    = 1000
  }

  # VM location & name
  node                 = var.proxmox_node
  template_name        = var.template_name
  template_description = var.template_description

  # Boot configuration
  boot      = "order=scsi2;scsi0;net0"
  boot_wait = "10s"
  boot_command = [
    # Go to boot menu
    "<esc><wait>",
    # Try and start preseed (will fail)
    "/install.amd/vmlinuz ",
    "initrd=/install.amd/initrd.gz ",
    "auto-install/enable=true ",
    "debconf/priority=critical ",
    "preseed/file=/mnt/cdrom2/preseed.cfg<enter><wait40>",
    # Switch to another terminal
    "<leftAltOn><f2><leftAltOff><wait3>",
    "<enter><wait3>",
    # Mount preseed iso
    "mkdir /mnt/cdrom2<enter>",
    "mount /dev/disk/by-label/PRESEED /mnt/cdrom2<enter><wait3>",
    # Back to main screen
    "<leftAltOn><f1><leftAltOff><wait3>",
    # Try to boot from file again (will work since it is now mounted)
    "<enter><wait><enter><wait><wait>",
    "<down><down><down><down><enter>"
  ]

  ssh_username           = var.user_username
  ssh_password           = "${local.bws_secrets["vm-template-user-password"]}"
  ssh_port               = var.ssh_port
  ssh_timeout            = "10m"
  ssh_pty                = true
  ssh_handshake_attempts = 3
}

build {
  sources = ["source.proxmox-iso.vm"]

  provisioner "shell" {
    # Run script as root
    execute_command = "echo ${local.bws_secrets["vm-template-user-password"]} | sudo -S {{.Vars}} bash {{.Path}}"
    script          = "scripts/provision.sh"
  }

  post-processor "manifest" {
    output = "output/manifest.json"
  }

  # Setting template with balooning device post-setup (debian install is unstable on ballooning device)
  post-processor "shell-local" {
    inline = [
      "PVE_URL='${local.bws_secrets["proxmox-api-endpoint"]}/api2/json'",
      "PVE_TOKEN='${local.bws_secrets["proxmox-root-api-token-id"]}=${local.bws_secrets["proxmox-root-api-token-secret"]}'",
      "NODE='${var.proxmox_node}'",
      "MEMORY_MAXIMUM='${var.memory_maximum}'",
      "MEMORY_MINIMUM='${var.memory_minimum}'",
      "VM_ID=$(jq -r '.builds[-1].artifact_id' output/manifest.json)",
      "curl -sS -k -X POST \"$PVE_URL/nodes/$NODE/qemu/$VM_ID/config\" \\",
      "     -H \"Authorization: PVEAPIToken=$PVE_TOKEN\" \\",
      "     --data \"memory=$MEMORY_MAXIMUM&balloon=$MEMORY_MINIMUM\""
    ]
  }
}
