package io.jenkins.plugins.entraoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.security.ACL;
import hudson.util.Secret;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.Test;

/**
 * JCasC tests for Entra credentials.
 */
@WithJenkinsConfiguredWithCode
public class EntraConfigurationAsCodeTest {

    /**
     * Verifies client secret credentials via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-client-secret.yml")
    public void supportsClientSecretCredentials(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraClientSecretCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraClientSecretCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraClientSecretCredentials c = credentials.get(0);
        assertEquals("Entra-client-secret", c.getId());
        assertEquals("organizations", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1, scope2", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());
        assertEquals("secret-value", Secret.toString(c.getClientSecret()));
    }

    /**
     * Verifies PFX credentials via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-cert-pfx.yml")
    public void supportsPfxCertificateCredentials(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraCertificatePfxCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraCertificatePfxCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraCertificatePfxCredentials c = credentials.get(0);
        assertEquals("Entra-cert-pfx", c.getId());
        assertEquals("tenant-guid", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());
        assertEquals("dGVzdA==", Secret.toString(c.getCertificateBase64()));
        assertEquals("pfx-password", Secret.toString(c.getCertificatePassword()));
    }

    /**
     * Verifies PEM credentials via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-cert-pem.yml")
    public void supportsPemCertificateCredentials(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraCertificatePemCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraCertificatePemCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraCertificatePemCredentials c = credentials.get(0);
        assertEquals("Entra-cert-pem", c.getId());
        assertEquals("tenant-guid", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());
        assertEquals(PemFixtures.CERT_PEM, Secret.toString(c.getCertificatePem()).trim());
        assertEquals(PemFixtures.KEY_PEM.trim(), Secret.toString(c.getPrivateKeyPem()).trim());
    }

    /**
     * Verifies PEM credentials with encrypted private key via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-cert-pem-encrypted.yml")
    public void supportsPemCertificateCredentialsWithEncryptedPrivateKey(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraCertificatePemCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraCertificatePemCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraCertificatePemCredentials c = credentials.get(0);
        assertEquals("Entra-cert-pem-encrypted", c.getId());
        assertEquals("tenant-guid", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());
        assertEquals(PemFixtures.CERT_PEM, Secret.toString(c.getCertificatePem()).trim());
        assertEquals("-----BEGIN ENCRYPTED PRIVATE KEY-----", Secret.toString(c.getPrivateKeyPem()).trim().split("\\R")[0]);
        assertEquals("changeit", Secret.toString(c.getPrivateKeyPassword()));
    }
}
