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

from adal import AuthenticationContext
from azure.keyvault import KeyVaultClient
from msrestazure.azure_active_directory import AdalAuthentication, MSIAuthentication
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logging.basicConfig(level=logging.INFO,
                    format='|%(asctime)s|%(levelname)-5s|%(process)d|%(thread)d|%(name)s|%(message)s')

_logger = logging.getLogger('keyvault-agent')

AZURE_AUTHORITY_SERVER = os.getenv('AZURE_AUTHORITY_SERVER', 'https://login.microsoftonline.com/')
VAULT_RESOURCE_NAME = os.getenv('VAULT_RESOURCE_NAME', 'https://vault.azure.net')


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
            self.tenant_id = sp_data['tenantId']
            self.client_id = sp_data['aadClientId']
            self.client_secret = sp_data['aadClientSecret']

        _logger.info('Parsing Service Principle file completed')

    def _get_client(self):
        if os.getenv("USE_MSI", "false").lower() == "true":
            _logger.info('Using MSI')
            credentials = MSIAuthentication(resource=VAULT_RESOURCE_NAME)
        else:
            self._parse_sp_file()
            authority = '/'.join([AZURE_AUTHORITY_SERVER.rstrip('/'), self.tenant_id])
            _logger.info('Using authority: %s', authority)
            context = AuthenticationContext(authority)
            _logger.info('Using vault resource name: %s and client id: %s', VAULT_RESOURCE_NAME, self.client_id)
            credentials = AdalAuthentication(context.acquire_token_with_client_credentials, VAULT_RESOURCE_NAME,
                                             self.client_id, self.client_secret)
        return KeyVaultClient(credentials)

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

    def _create_kubernetes_secret_objects(self, key, value):
        key = key.lower()
        api_instance = self._get_kubernetes_api_instance()
        secret = client.V1Secret()
        encoded_secret = base64.b64encode(bytes(value))

        secret.metadata = client.V1ObjectMeta(name=key)
        secret.type = "Opaque"
        secret.data = { "secret" : encoded_secret }

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

        client = self._get_client()
        _logger.info('Using vault: %s', vault_base_url)

        # Retrieving all secrets from Key Vault if specified by user
        if secrets_keys is None:
            _logger.info('Retrieving all secrets from Key Vault.')

            all_secrets = list(client.get_secrets(vault_base_url))
            secrets_keys = ';'.join([secret.id.split('/')[-1] for secret in all_secrets])

        if secrets_keys is not None:
            for key_info in filter(None, secrets_keys.split(';')):
                key_name, key_version, cert_filename, key_filename = self._split_keyinfo(key_info)
                _logger.info('Retrieving secret name:%s with version: %s output certFileName: %s keyFileName: %s', key_name, key_version, cert_filename, key_filename)
                secret = client.get_secret(vault_base_url, key_name, key_version)
                
                self._create_kubernetes_secret_objects(key_name, secret.value)

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

        client = self._get_client()
        _logger.info('Using vault: %s', vault_base_url)

        if secrets_keys is not None:
            for key_info in filter(None, secrets_keys.split(';')):
                # Secrets are not renamed. They will have same name
                # Certs and keys can be renamed
                key_name, key_version, cert_filename, key_filename = self._split_keyinfo(key_info)
                _logger.info('Retrieving secret name:%s with version: %s output certFileName: %s keyFileName: %s', key_name, key_version, cert_filename, key_filename)
                secret = client.get_secret(vault_base_url, key_name, key_version)
                
                if secret.kid is not None:
                    _logger.info('Secret is backing certificate. Dumping private key and certificate.')
                    if secret.content_type == 'application/x-pkcs12':
                        self._dump_pfx(secret.value, cert_filename, key_filename)
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
                cert = client.get_certificate(vault_base_url, key_name, key_version)
                output_path = os.path.join(self._certs_output_folder, cert_filename)
                _logger.info('Dumping cert value to: %s', output_path)
                with open(output_path, 'w') as cert_file:
                    cert_file.write(self._cert_to_pem(cert.cer))

    def _dump_pfx(self, pfx, cert_filename, key_filename):
        from OpenSSL import crypto
        p12 = crypto.load_pkcs12(base64.decodestring(pfx))
        pk = crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey())
        certs = (p12.get_certificate(),) + (p12.get_ca_certificates() or ())

        if (cert_filename == key_filename):
            key_path = os.path.join(self._keys_output_folder, key_filename)
            cert_path = os.path.join(self._certs_output_folder, cert_filename)
        else:
            # write to certs_keys folder when cert_filename and key_filename specified
            key_path = os.path.join(self._cert_keys_output_folder, key_filename)
            cert_path = os.path.join(self._cert_keys_output_folder, cert_filename)

        _logger.info('Dumping key value to: %s', key_path)
        with open(key_path, 'w') as key_file:
            key_file.write(pk)

        _logger.info('Dumping certs to: %s', cert_path)
        with open(cert_path, 'w') as cert_file:
            for cert in certs:
                cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    @staticmethod
    def _dump_secret(secret):
        value = secret.value
        if secret.tags is not None and 'file-encoding' in secret.tags:
            encoding = secret.tags['file-encoding']
            if encoding == 'base64':
                value = base64.decodestring(value)

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
        encoded = base64.encodestring(cert)
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
