#  Copyright 2022 Collate
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""
Secrets manager implementation using AWS Secrets Manager
"""
# Import the Secret Manager client library.
from google.cloud import secretmanager
from google.cloud import google_crc32c
from typing import Optional
from metadata.utils.secrets.external_secrets_manager import ExternalSecretsManager
from metadata.generated.schema.security.secrets.secretsManagerProvider import (
    SecretsManagerProvider,
)
from metadata.utils.logger import utils_logger


# GCP project in which to store secrets in Secret Manager.
project_id = "YOUR_PROJECT_ID"

# ID of the secret to create.
secret_id = "YOUR_SECRET_ID"

# Create the Secret Manager client.
client = secretmanager.SecretManagerServiceClient()

# Build the parent name from the project.
parent = f"projects/{project_id}"


class GoogleSecretsManager(ExternalSecretsManager):
    """
    Secrets Manager Implementation Class
    """

    def __init__(self):
        super().__init__("secretsmanager", SecretsManagerProvider.google_secret_manager)

    def get_string_value(self, secret_id: str, project_id: str, version_id: str) -> Optional[str]:
        """
        :param secret_id: The secret id to retrieve. Current stage is always retrieved.
        :return: The value of the secret. When the secret is a string, the value is
                 contained in the `SecretString` field. When the secret is bytes or not present,
                 it throws a `ValueError` exception.
        """

        # Create the Secret Manager client.
        client = secretmanager.SecretManagerServiceClient()

        # Build the resource name of the secret version.
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

        # Access the secret version.
        response = client.access_secret_version(request={"name": name})


        if secret_id or version_id or project_id is None:
            raise ValueError("[name] argument is None")

        # Verify payload checksum.
        crc32c = google_crc32c.Checksum()
        crc32c.update(response.payload.data)
        if response.payload.data_crc32c != int(crc32c.hexdigest(), 16):
            print("Data corruption detected.")
            return response

        # Print the secret payload.
        #
        # WARNING: Do not print the secret in a production environment - this
        # snippet is showing how to access the secret material.
        payload = response.payload.data.decode("UTF-8")
        print("Plaintext: {}".format(payload))

