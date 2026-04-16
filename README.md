# Kubernetes Golden Image

This repository contains the Packer configuration required to create a golden ISO image for the Kubernetes nodes running on the Proxmox environment.

## Usage Instructions

Run the following steps only during the initial setup:

1. **Download required plugins:**

    ```sh
    packer init .
    ```

1. **Create a variables file:**

    ```sh
    touch variables.auto.pkrvars
    ```

1. **Populate the variables file:** Add your Bitwarden Secrets Manager credentials:

    ```text
    bws_token      = "<bws-machine-account-token>"
    bws_project_id = "<bws-project-id>"
    ```

Run the following steps for each VM template creation:

1. **Format and validate the code:**

    ```sh
    packer fmt .
    packer validate .
    ```

1. **Run the build:**

    ```sh
    packer build . -force
    ```

## VM ID Allocation

VM IDs are assigned systematically based on the build context:

- **VM ID 101:** Used for VM templates created by CI/CD from the main branch (Production).
- **VM ID 102:** Used for VM templates created by CI/CD from pull requests targeting the main branch (Validation).
- **VM ID 103:** Used for VM templates created by CI/CD from any branch other than main (Testing).
- **VM ID 104:** Used for VM templates created when running a build manually from a local machine.
