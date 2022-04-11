# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

import sys
import os
import json
import logging
import base64
import requests

from kubernetes import client, config
from OpenSSL import crypto
from azure.keyvault.secrets import SecretClient
from azure.keyvault.certificates import CertificateClient
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential, ClientSecretCredential


logging.basicConfig(level=logging.INFO,
                    format='|%(asctime)s|%(levelname)-5s|%(process)d|%(thread)d|%(name)s|%(message)s')

_logger = logging.getLogger('keyvault-agent')
logging_core_pipeline = logging.getLogger('azure.core.pipeline.policies.http_logging_policy')
logging_core_pipeline.setLevel(logging.WARNING)

AZURE_AUTHORITY_SERVER = os.getenv('AZURE_AUTHORITY_SERVER', 'https://login.microsoftonline.com/')
TIMEOUT = int(os.getenv('TIMEOUT', '300'))

class KeyVaultAgent(object):
    """
    A Key Vault agent that reads secrets from Key Vault and stores them in a folder
    """

    def __init__(self):
        self._secrets_output_folder = None
        self._certs_output_folder = None
        self._keys_output_folder = None
        self._cert_keys_output_folder = None
        self._api_instance = None
        self._secrets_list = None
        self._secrets_namespace = None

    def _parse_sp_file(self):
        file_path = os.getenv('SERVICE_PRINCIPLE_FILE_PATH')
        _logger.info('Parsing Service Principle file from: %s', file_path)
        if not os.path.isfile(file_path):
            raise Exception("Service Principle file doesn't exist: %s" % file_path)

        with open(file_path, 'r') as sp_file:
            sp_data = json.load(sp_file)
            # retrieve the relevant values used to authenticate with Key Vault
            self.tenant_id = self._get_tenant_id(sp_data['tenantId'])
            self.client_id = sp_data['aadClientId']
            self.client_secret = sp_data['aadClientSecret']

            # in case use msi, potentially we could get mi client id from sp file as well
            if self.client_id == "msi" and self.client_secret == "msi":
                self.user_assigned_identity_id = sp_data.get("userAssignedIdentityID", "")

        _logger.info('Parsing Service Principle file completed')

    def _parse_sp_env(self):
        self.tenant_id = os.environ["TENANT_ID"]
        self.client_id = os.environ["CLIENT_ID"]
        self.client_secret = os.environ["CLIENT_SECRET"]

        _logger.info('Assign new azure identity env variable')
        os.environ["AZURE_TENANT_ID"] = self.tenant_id
        os.environ["AZURE_CLIENT_ID"] = self.client_id
        os.environ["AZURE_CLIENT_SECRET"] = self.client_secret

        _logger.info('Parsing Service Principle env completed')
    
    def _get_credential(self):
        if os.getenv("USE_MSI", "false").lower() == "true":
            _logger.info('Using MSI')
            if "MSI_CLIENT_ID" in os.environ:
                msi_client_id = os.environ["MSI_CLIENT_ID"]
                _logger.info('Using client_id: %s', msi_client_id)
                credentials = ManagedIdentityCredential(client_id=msi_client_id)
            elif "MSI_OBJECT_ID" in os.environ:
                msi_object_id = os.environ["MSI_OBJECT_ID"]
                identity = {'object_id': msi_object_id}
                _logger.info('Using object_id: %s', msi_object_id)
                credentials = ManagedIdentityCredential(identity_config=identity)
            elif "MSI_RESOURCE_ID" in os.environ:
                msi_resource_id = os.environ["MSI_RESOURCE_ID"]
                identity = {'resource_id': msi_resource_id}
                _logger.info('Using resource_id: %s', msi_resource_id)
                credentials = ManagedIdentityCredential(identity_config=identity)
            else:
                credentials = ManagedIdentityCredential()
        else:
            if os.getenv("USE_ENV", "false").lower() == "true":
                self._parse_sp_env()
            else:
                self._parse_sp_file()
            # azure.json file will have "msi" as the client_id and client_secret
            # if the node is running managed identity
            if self.client_id == "msi" and self.client_secret == "msi":
                _logger.info('Using MSI')
                # refer _parse_sp_file, potentially we could have mi client id from sp
                if self.user_assigned_identity_id != "":
                    _logger.info('Using client_id: %s', self.user_assigned_identity_id)
                    credentials = ManagedIdentityCredential(client_id=self.user_assigned_identity_id)
                else:
                    credentials = DefaultAzureCredential()
            else:
                _logger.info('Using ClientSecretCredential')
                principal = {
                    'tenant_id': self.tenant_id,
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                }
                credentials = ClientSecretCredential(**principal, authority=AZURE_AUTHORITY_SERVER)
        return credentials

    def _get_tenant_id(self, tenant_id_from_config):
        if os.getenv('AUTO_DETECT_AAD_TENANT', 'false').lower() != 'true':
            _logger.info('AAD tenant auto detection turned off. Using tenant id %s from cloud config', tenant_id_from_config)
            return tenant_id_from_config

        # if we are unable to auto detect tenant id for any reason, we will use the one from config
        try:
            vault_base_url = os.getenv('VAULT_BASE_URL')
            _logger.info('AAD tenant auto detection turned on. Detecting tenant id for %s', vault_base_url)
            # Send request pointing to any key to trigger a 401
            URL = '{}/keys/somekeyname/1?api-version=2018-02-14'.format(vault_base_url)
            _logger.info('Sending challenge request to %s', URL)
            response = requests.get(url = URL)
            if response.status_code == 401:
                # If status code == HTTP 401, then parse the WWW-Authenticate header to retrieve 'authorization' value
                # Bearer authorization="https://login.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47", resource=".."
                challenge = response.headers['WWW-authenticate'].lower()
                challenge_data = challenge.replace('bearer ', '').split(',')
                for kvp in challenge_data:
                    keyvalue = kvp.strip().split('=')
                    if len(keyvalue) == 2 and keyvalue[0] == 'authorization':
                        authority = keyvalue[1].replace('"', '')
                        try:
                            # This API is available only in Python 3
                            from urllib.parse import urlparse
                        except ImportError:
                            from urlparse import urlparse
                        tenant_id = urlparse(authority).path.replace('/', '')
                        _logger.info('Successfully auto detected tenant id : %s', tenant_id)
                        return tenant_id

                # if we cannot find in the for loop default the value and log
                _logger.error('Unable to find the tenant id from the received challenge [%s]. Using tenant id from config', challenge)

            # if conditions are not met return the default tenant_id_from_config from cloud config file
            _logger.info('Unable to receive a challenge to auto detect AAD tenant. Received status code %d. Expected status code : 401. Using the config default %s', response.status_code, tenant_id_from_config)
        except:
            _logger.error('Exception occured while trying to auto detect AAD tenant. Using the config default %s', tenant_id_from_config)
        return tenant_id_from_config

    def _get_kubernetes_api_instance(self):
        if self._api_instance is None:
            config.load_incluster_config()
            client.configuration.assert_hostname = False
            self._api_instance = client.CoreV1Api()

        return self._api_instance

    def _get_kubernetes_secrets_list(self):
        if self._secrets_list is None:
            api_instance = self._get_kubernetes_api_instance()
            api_response = api_instance.list_namespaced_secret(namespace=self._secrets_namespace)

            secret_name_list = []
            should_continue = True

            while should_continue is True:
                continue_value = api_response.metadata._continue
                secrets_list = api_response.items
                for item in secrets_list:
                    secret_name_list.append(item.metadata.name)

                if continue_value is not None:
                    api_response = api_instance.list_namespaced_secret(namespace=self._secrets_namespace, _continue = continue_value)
                else:
                    should_continue = False

            self._secrets_list = secret_name_list

        return self._secrets_list

    def _create_kubernetes_secret_objects(self, key, secret_value, secret_type):
        key = key.lower()
        api_instance = self._get_kubernetes_api_instance()
        secret = client.V1Secret()

        secret.metadata = client.V1ObjectMeta(name=key)
        secret.type = secret_type

        if secret.type == 'kubernetes.io/tls':
            _logger.info('Extracting private key and certificate.')
            p12 = crypto.load_pkcs12(base64.b64decode(secret_value))
            secret_download_ca_override_env_key = key.upper() + "_DOWNLOAD_CA_CERTIFICATE"
            ca_certs = ()
            if os.getenv(secret_download_ca_override_env_key, os.getenv('DOWNLOAD_CA_CERTIFICATES','true')).lower() == "true":
                ca_certs = (p12.get_ca_certificates() or ())
                certs = (p12.get_certificate(),) + ca_certs
            else:
                certs = (p12.get_certificate(),)
            privateKey = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
            certString = ""
            for cert in certs:
                certString += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
            secret.data = { 'tls.crt' : base64.b64encode(certString.encode()).decode(), 'tls.key' : base64.b64encode(privateKey).decode() }
            if ca_certs:
                ca_certs_string = ""
                for cert in ca_certs:
                    ca_certs_string += crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
                secret.data.update({'ca.crt': base64.b64encode(ca_certs_string.encode()).decode()})

        else:
            secretDataKey = key.upper() + "_SECRETS_DATA_KEY"
            secret_data_key = os.getenv(secretDataKey, 'secret')
            secret.data = { secret_data_key : base64.b64encode(secret_value.encode()).decode() }

        secrets_list = self._get_kubernetes_secrets_list()

        _logger.info('Creating or updating Kubernetes Secret object: %s', key)
        try:
            if key in secrets_list:
                api_instance.patch_namespaced_secret(name=key, namespace=self._secrets_namespace, body=secret)
            else:
                api_instance.create_namespaced_secret(namespace=self._secrets_namespace, body=secret)
        except:
            _logger.exception("Failed to create or update Kubernetes Secret")

    def grab_secrets_kubernetes_objects(self):
        """
        Gets secrets from KeyVault and creates them as Kubernetes secrets objects
        """
        vault_base_url = os.getenv('VAULT_BASE_URL')
        secrets_keys = os.getenv('SECRETS_KEYS')
        self._secrets_namespace = os.getenv('SECRETS_NAMESPACE','default')

        credential = self._get_credential()
        secret_client = SecretClient(vault_url=vault_base_url, credential=credential, timeout=TIMEOUT)
        _logger.info('Using vault: %s', vault_base_url)

        # Retrieving all secrets from Key Vault if specified by user
        if secrets_keys is None:
            _logger.info('Retrieving all secrets from Key Vault.')

            all_secrets = list(secret_client.list_properties_of_secrets())
            secrets_keys = ';'.join([secret.id.split('/')[-1] for secret in all_secrets])

        if secrets_keys is not None:
            for key_info in filter(None, secrets_keys.split(';')):
                key_name, key_version, cert_filename, key_filename = self._split_keyinfo(key_info)
                _logger.info('Retrieving secret name:%s with version: %s output certFileName: %s keyFileName: %s', key_name, key_version, cert_filename, key_filename)
                secret = secret_client.get_secret(key_name, key_version)

                secret_type_env_key = key_name.upper() + "_SECRET_TYPE"
                secret_type = os.getenv(secret_type_env_key, os.getenv("SECRETS_TYPE", 'Opaque'))
                if secret_type == 'kubernetes.io/tls':
                    if secret.properties.key_id is not None:
                        _logger.info('Secret is backing certificate.')
                        if secret.properties.content_type == 'application/x-pkcs12':
                            self._create_kubernetes_secret_objects(key_name, secret.value, secret_type)
                        else:
                            _logger.error('Secret is not in pkcs12 format')
                            sys.exit(1)
                    elif (key_name != cert_filename):
                        _logger.error('Cert filename provided for secret %s not backing a certificate.', key_name)
                        sys.exit(('Error: Cert filename provided for secret {0} not backing a certificate.').format(key_name))
                else:
                    self._create_kubernetes_secret_objects(key_name, secret.value, secret_type)

    def grab_secrets(self):
        """
        Gets secrets from KeyVault and stores them in a folder
        """
        vault_base_url = os.getenv('VAULT_BASE_URL')
        secrets_keys = os.getenv('SECRETS_KEYS')
        certs_keys = os.getenv('CERTS_KEYS')
        output_folder = os.getenv('SECRETS_FOLDER')
        self._secrets_output_folder = os.path.join(output_folder, "secrets")
        self._certs_output_folder = os.path.join(output_folder, "certs")
        self._keys_output_folder = os.path.join(output_folder, "keys")
        self._cert_keys_output_folder = os.path.join(output_folder, "certs_keys")

        for folder in (self._secrets_output_folder, self._certs_output_folder, self._keys_output_folder, self._cert_keys_output_folder):
            if not os.path.exists(folder):
                os.makedirs(folder)

        credential = self._get_credential()
        secret_client = SecretClient(vault_url=vault_base_url, credential=credential, timeout=TIMEOUT)
        certificate_client = CertificateClient(vault_url=vault_base_url, credential=credential, timeout=TIMEOUT)
        _logger.info('Using vault: %s', vault_base_url)

        # Retrieving all secrets from Key Vault if specified by user
        if secrets_keys is None:
            _logger.info('Retrieving all secrets from Key Vault.')

            all_secrets = list(secret_client.list_properties_of_secrets())
            secrets_keys = ';'.join([secret.id.split('/')[-1] for secret in all_secrets])

        if secrets_keys is not None:
            for key_info in filter(None, secrets_keys.split(';')):
                # Secrets are not renamed. They will have same name
                # Certs and keys can be renamed
                key_name, key_version, cert_filename, key_filename = self._split_keyinfo(key_info)
                _logger.info('Retrieving secret name:%s with version: %s output certFileName: %s keyFileName: %s', key_name, key_version, cert_filename, key_filename)
                secret = secret_client.get_secret(key_name, key_version)

                if secret.properties.key_id is not None:
                    _logger.info('Secret is backing certificate. Dumping private key and certificate.')
                    if secret.properties.content_type == 'application/x-pkcs12':
                        self._dump_pfx(secret.value, cert_filename, key_filename, key_name)
                    else:
                        _logger.error('Secret is not in pkcs12 format')
                        sys.exit(1)
                elif (key_name != cert_filename):
                    _logger.error('Cert filename provided for secret %s not backing a certificate.', key_name)
                    sys.exit(('Error: Cert filename provided for secret {0} not backing a certificate.').format(key_name))

                # secret has same name as key_name
                output_path = os.path.join(self._secrets_output_folder, key_name)
                _logger.info('Dumping secret value to: %s', output_path)
                with open(output_path, 'w') as secret_file:
                    secret_file.write(self._dump_secret(secret))

        if certs_keys is not None:
            for key_info in filter(None, certs_keys.split(';')):
                # only cert_filename is needed, key_filename is ignored with _
                key_name, key_version, cert_filename, _ = self._split_keyinfo(key_info)
                _logger.info('Retrieving cert name:%s with version: %s output certFileName: %s', key_name, key_version, cert_filename)
                cert = certificate_client.get_certificate_version(key_name, key_version)
                output_path = os.path.join(self._certs_output_folder, cert_filename)
                _logger.info('Dumping cert value to: %s', output_path)
                with open(output_path, 'w') as cert_file:
                    cert_file.write(self._cert_to_pem(cert.cer))

    def _dump_pfx(self, pfx, cert_filename, key_filename, key_name):
        p12 = crypto.load_pkcs12(base64.b64decode(pfx))
        pk = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        secret_download_ca_override_env_key = key_name.upper() + "_DOWNLOAD_CA_CERTIFICATE"
        if os.getenv(secret_download_ca_override_env_key, os.getenv('DOWNLOAD_CA_CERTIFICATES','true')).lower() == "true":
            certs = (p12.get_certificate(),) + (p12.get_ca_certificates() or ())
        else:
            certs = (p12.get_certificate(),)

        if (cert_filename == key_filename):
            key_path = os.path.join(self._keys_output_folder, key_filename)
            cert_path = os.path.join(self._certs_output_folder, cert_filename)
            pfx_path = os.path.join(self._keys_output_folder, key_filename + ".pfx")
        else:
            # write to certs_keys folder when cert_filename and key_filename specified
            key_path = os.path.join(self._cert_keys_output_folder, key_filename)
            cert_path = os.path.join(self._cert_keys_output_folder, cert_filename)
            pfx_path = os.path.join(self._cert_keys_output_folder, key_filename + ".pfx")

        _logger.info('Dumping key value to: %s', key_path)
        with open(key_path, 'w') as key_file:
            key_file.write(pk.decode())

        # Saves the PFX file together with the key file (with .pfx extension).
        # As it contains key material, we save it to the same place as keys.
        if os.getenv('SAVE_PFX','false').lower() == "true":
            _logger.info('Dumping PFX to: %s', pfx_path)

            with open(pfx_path, 'wb') as pfx_file:
                pfx_file.write(base64.b64decode(pfx))

        _logger.info('Dumping certs to: %s', cert_path)
        with open(cert_path, 'w') as cert_file:
            for cert in certs:
                cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())

    @staticmethod
    def _dump_secret(secret):
        value = secret.value
        tags = secret.properties.tags
        if tags is not None and 'file-encoding' in tags:
            encoding = tags['file-encoding']
            if encoding == 'base64':
                value = base64.b64decode(value)

        return value

    @staticmethod
    def _split_keyinfo(key_info):
        key_parts = key_info.strip().split(':')
        key_name = key_parts[0]
        key_version = '' if len(key_parts) < 2 else key_parts[1]
        cert_filename = key_name if len(key_parts) < 3 else key_parts[2]

        # key_filename set to cert_filename when only cert_filename is given
        # key_filename default to key_name when cert and key filenames are not given
        key_filename = cert_filename if len(key_parts) < 4 else key_parts[3]

        return key_name, key_version, cert_filename, key_filename

    @staticmethod
    def _cert_to_pem(cert):
        encoded = base64.encodebytes(cert)
        if isinstance(encoded, bytes):
            encoded = encoded.decode("utf-8")
        encoded = '-----BEGIN CERTIFICATE-----\n' + encoded + '-----END CERTIFICATE-----\n'

        return encoded


if __name__ == '__main__':
    _logger.info('Grabbing secrets from Key Vault')
    if os.getenv('CREATE_KUBERNETES_SECRETS','false').lower() == "true":
        KeyVaultAgent().grab_secrets_kubernetes_objects()
    else:
        KeyVaultAgent().grab_secrets()
    _logger.info('Done!')
