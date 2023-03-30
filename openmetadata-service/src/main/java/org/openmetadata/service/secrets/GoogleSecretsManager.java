package org.openmetadata.service.secrets;

import com.google.cloud.secretmanager.v1.*;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.util.zip.CRC32C;
import java.util.zip.Checksum;
import org.openmetadata.schema.security.secrets.SecretsManagerProvider;

public class GoogleSecretsManager extends GoogleBasedSecretsManager {

    private static GoogleSecretsManager INSTANCE = null;
    private SecretManagerServiceClient secretsClient;
    private String projectID = "";

    ProjectName projectName;

    protected GoogleSecretsManager(String clusterPrefix) throws IOException {
        super(SecretsManagerProvider.GOOGLE_SECRET_MANAGER, clusterPrefix);
    }

    void initClient() throws IOException {
        this.secretsClient = SecretManagerServiceClient.create();
    }

    void initProjectIDAndProjectName(String projectID) throws IOException {
        this.projectID = projectID;
        projectName = ProjectName.of(projectID);
    }

    @Override
    void storeSecret(String secretID, String secretValue) {
        SecretName secretName = SecretName.of(projectID, secretID);
        // Build the secret to create.
        Secret secret =
                Secret.newBuilder()
                        .setReplication(Replication.newBuilder().setAutomatic(Replication.Automatic.newBuilder().build()).build())
                        .build();

        // Create the secret.
        Secret createdSecret = this.secretsClient.createSecret(projectName, secretID, secret);
        System.out.printf("Created secret %s\n", createdSecret.getName());

        updateSecret(String.valueOf(secretName), secretValue);
    }

    @Override
    void updateSecret(String secretName, String secretValue) {
        byte[] data = secretValue.getBytes();
        // Calculate data checksum. The library is available in Java 9+.
        // If using Java 8, the following library may be used:
        // https://cloud.google.com/appengine/docs/standard/java/javadoc/com/google/appengine/api/files/Crc32c
        Checksum checksum = new CRC32C();
        checksum.update(data, 0, data.length);

        // Create the secret payload.
        SecretPayload payload =
                SecretPayload.newBuilder()
                        .setData(ByteString.copyFrom(data))
                        // Providing data checksum is optional.
                        .setDataCrc32C(checksum.getValue())
                        .build();

        // Add the secret version.
        SecretVersion version = this.secretsClient.addSecretVersion(secretName, payload);
        System.out.printf("Added secret version %s\n", version.getName());
    }

    @Override
    String getSecret(String secretVersionName) {
        // Access the secret version.
        AccessSecretVersionResponse response = this.secretsClient.accessSecretVersion(secretVersionName);

        // Verify checksum. The used library is available in Java 9+.
        // If using Java 8, you may use the following:
        // https://github.com/google/guava/blob/e62d6a0456420d295089a9c319b7593a3eae4a83/guava/src/com/google/common/hash/Hashing.java#L395
        byte[] data = response.getPayload().getData().toByteArray();
        Checksum checksum = new CRC32C();
        checksum.update(data, 0, data.length);
        if (response.getPayload().getDataCrc32C() != checksum.getValue()) {
            return "Data Corruption Detected";
        }

        // Print the secret payload.
        return response.getPayload().getData().toStringUtf8();
    }

    public static GoogleSecretsManager getInstance(String clusterPrefix) throws IOException {
        if (INSTANCE == null) INSTANCE = new GoogleSecretsManager(clusterPrefix);
        return INSTANCE;
    }
}
