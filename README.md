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
packer fmt .
packer validate .
```

Run the code:
```sh
packer build .
```