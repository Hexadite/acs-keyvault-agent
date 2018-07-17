# Azure Key Vault Agent for ACS (Kubernetes)
An Azure Key Vault agent container that grabs secrets from Azure Key Vault securely and passes them to other containers in its pod, either by shared volume or Kubernetes secrets objects

# How does it work?
The Azure Key Vault agent container does the following - 
* It runs before any other container as an init-container
* It connects to Azure Key Vault using the cluster's service principle
* It then grabs the desired secrets and/or certificates from Azure Key Vault and stores them in a shared volume (memory only - tmpfs)
* If a secret refers to a key that is backing a certificate, both private key and certificate are exported as pem
* It terminates and let other containers run
* Finally, other containers have access to the secrets using a shared volume
When creating Kubernetes secrets objects - 
* It connects to Azure Key Vault using the cluster's service principle
* It then grabs the desired secrets from Azure Key Vault and stores them as Kubernetes secrets objects. These objects are stored unencrypted by default in etcd, and are readable by other pods in the namespace.

# Advantages
* Secrets are stored securely in Azure Key Vault
* Authentication to Azure Key Vault is done securely without any secrets or config maps being used

# Requirements
* A deployed Azure Key Vault
* A Kubernetes cluster with a working `kubectl`
* The Kubernetes cluster's Service principal is added to the Access policies of the Key Vault

# How to use it
* Config your Azure Key Vault to give your cluster's service principle a "get" permission so it can grab secrets
* Clone the project to your desired folder 
* Build the agent image using docker
```
cd <project_root>
docker build . -t <image_tag>
```
* Push the agent image to your image repository
```
docker push <image_tag>
```

* Edit `examples/acs-keyvault-deployment.yaml` file and change - 
  * `<IMAGE_PATH>` - the image you just built earlier.
  * `<VAULT_URL>` - should be something like: `https://<NAME>.vault.azure.net`.
  * `<SECRET_KEYS>` - a list of keys and their versions (optional), represented as a string, formatted like: `<secret_name>:<secret_version>;<another_secret>`. If a secret is backing a certificate, private key and certificate will be downloaded in PEM format at `keys/` and `certs/` respectively. 
  for example
  `mysecret:9d90276b377b4d9ea10763c153a2f015;anotherone;`
  * `<CERTS_KEYS>` - a list of certificates and their versions (optional), represented as a string, formatted like: `<cert_name>:<cert_version>;<another_cert>`. Certificates will be downloaded in PEM format. 
  

* Create the deployment using
```
kubectl create -f ./examples/acs-keyvault-deployment.yaml
```
* Now connect to any of the deployment pods -
```
kubectl exec -ti test-keyvault-7d94566cdb-7wmx9 -c test-app /bin/sh
```
and now just view the secrets with 
```
cat /secrets/secrets/<secret_name>
cat /secrets/certs/<certificate_name>
cat /secrets/keys/<key_name>
```

# How to use it - Kubernetes Secrets
* Config your Azure Key Vault to give your cluster's service principle a "get" permission so it can grab secrets
* Ensure that your secret names follow Kubernetes standard - must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
* Clone the project to your desired folder 
* Build the agent image using docker
```
cd <project_root>
docker build . -t <image_tag>
```
* Push the agent image to your image repository
```
docker push <image_tag>
```
* Edit `examples/acs-keyvault-cronjob.yaml` or `examples/acs-keyvault-deployment.yaml` file and change the following:
* If you'd like to get all keys from Key Vault dynamically, make sure to remove the SECRET_KEYS variable entirely.
  * `<IMAGE_PATH>` - the image you just built earlier.
  * `<VAULT_URL>` - should be something like: `https://<NAME>.vault.azure.net`.
  * `<CREATE_KUBERNETES_SECRETS>` - "true" or "false", whether or not you'd like kubernetes secrets objects created.
  * `<SECRETS_NAMESPACE>` - a string value if you want to use a namespace other than default.
  * `<SECRET_KEYS>` - a list of keys and their versions (optional), represented as a string, formatted like: `<secret_name>:<secret_version>;<another_secret>`. If a secret is backing a certificate, private key and certificate will be downloaded in PEM format at `keys/` and `certs/` respectively. 
  for example
  `mysecret:9d90276b377b4d9ea10763c153a2f015;anotherone;`
* View secrets
```
kubectl get secrets
```

# Logs
* View init container logs:
```
kubectl logs <Pod ID> -c keyvault-agent
```
