# kubernetes-golden-image
Golden ISO image for my Kubernetes nodes

## How to run
Run only on initial setup:
- Download plugins:
    ```sh
    packer init .
    ```
Create a variables file:
```sh
touch variables.auto.pkrvars
```
- Then put the variables name and value in a key=value format

Validate the code:
```sh
packer fmt .
packer validate .
```
Run the code:
```sh
packer build .
```