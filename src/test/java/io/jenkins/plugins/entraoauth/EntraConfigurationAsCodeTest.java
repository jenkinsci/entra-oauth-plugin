package io.jenkins.plugins.entraoauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
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
     * Verifies client secret authentication via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-client-secret.yml")
    public void supportsClientSecretAuthentication(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraOAuthCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraOAuthCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraOAuthCredentials c = credentials.get(0);
        assertEquals("entra-client-secret", c.getId());
        assertEquals("organizations", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1, scope2", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());

        EntraClientSecretAuthMethod method = assertInstanceOf(EntraClientSecretAuthMethod.class, c.getAuthenticationMethod());
        assertEquals("secret-value", Secret.toString(method.getClientSecret()));
    }

    /**
     * Verifies PFX authentication via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-cert-pfx.yml")
    public void supportsPfxAuthentication(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraOAuthCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraOAuthCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraOAuthCredentials c = credentials.get(0);
        assertEquals("entra-cert-pfx", c.getId());
        assertEquals("tenant-guid", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());

        EntraPfxAuthMethod method = assertInstanceOf(EntraPfxAuthMethod.class, c.getAuthenticationMethod());
        assertEquals("dGVzdA==", Secret.toString(method.getCertificateBase64()));
        assertEquals("pfx-password", Secret.toString(method.getCertificatePassword()));
    }

    /**
     * Verifies PEM authentication via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-cert-pem.yml")
    public void supportsPemAuthentication(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraOAuthCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraOAuthCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraOAuthCredentials c = credentials.get(0);
        assertEquals("entra-cert-pem", c.getId());
        assertEquals("tenant-guid", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());

        EntraPemAuthMethod method = assertInstanceOf(EntraPemAuthMethod.class, c.getAuthenticationMethod());
        assertEquals(PemFixtures.CERT_PEM, Secret.toString(method.getCertificatePem()).trim());
        assertEquals(PemFixtures.KEY_PEM.trim(), Secret.toString(method.getPrivateKeyPem()).trim());
    }

    /**
     * Verifies encrypted PEM private key authentication via JCasC.
     */
    @Test
    @ConfiguredWithCode("entra-cert-pem-encrypted.yml")
    public void supportsEncryptedPemAuthentication(JenkinsConfiguredWithCodeRule ignored) {
        List<EntraOAuthCredentials> credentials = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraOAuthCredentials.class, Jenkins.get(), ACL.SYSTEM2, Collections.emptyList());
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraOAuthCredentials c = credentials.get(0);
        assertEquals("entra-cert-pem-encrypted", c.getId());

        EntraPemAuthMethod method = assertInstanceOf(EntraPemAuthMethod.class, c.getAuthenticationMethod());
        assertEquals("-----BEGIN ENCRYPTED PRIVATE KEY-----", Secret.toString(method.getPrivateKeyPem()).trim().split("\\R")[0]);
        assertEquals("changeit", Secret.toString(method.getPrivateKeyPassword()));
    }
}
