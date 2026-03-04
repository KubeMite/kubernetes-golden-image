# kubernetes-golden-image
Golden ISO image for my Kubernetes nodes

## How to run
Run only on initial setup:
- Download plugins:
    ```sh
    packer init .
    ```
- Create a variables file:
```sh
touch variables.auto.pkrvars
```
- Then put the following variables in that file:
```
bws_token      = "<bws-machine-account-token>"
bws_project_id = "<bws-project-id>"
```

Format the code:
```sh
packer fmt .
```

Validate the code:
```sh
packer validate .
```

Run the code:
```sh
packer build . -force
```

## How are VM IDs chosen?

- VM ID 101 - used for VM templates created by CI/CD from the main branch, used for production
- VM ID 102 - used for VM templates created by CI/CD from pull requests to the main branch, used for validation
- VM ID 103 - used for VM templates created by CI/CD from any branch that is not the main branch, used for testing
- VM ID 104 - used for VM templates created when running a build manually from a local machine