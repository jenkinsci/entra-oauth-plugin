package io.jenkins.plugins.entraoauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.util.Secret;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;

/**
 * JCasC tests for Entra credentials.
 */
public class EntraConfigurationAsCodeTest {

    @Rule
    public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    /**
     * Verifies client secret credentials via JCasC.
     */
    @Test
    @ConfiguredWithCode("Entra-client-secret.yml")
    public void supportsClientSecretCredentials() {
        List<EntraClientSecretCredentials> credentials =
                CredentialsProvider.lookupCredentials(EntraClientSecretCredentials.class);
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
    @ConfiguredWithCode("Entra-cert-pfx.yml")
    public void supportsPfxCertificateCredentials() {
        List<EntraCertificatePfxCredentials> credentials =
                CredentialsProvider.lookupCredentials(EntraCertificatePfxCredentials.class);
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
    @ConfiguredWithCode("Entra-cert-pem.yml")
    public void supportsPemCertificateCredentials() {
        List<EntraCertificatePemCredentials> credentials =
                CredentialsProvider.lookupCredentials(EntraCertificatePemCredentials.class);
        assertNotNull(credentials);
        assertEquals(1, credentials.size());
        EntraCertificatePemCredentials c = credentials.get(0);
        assertEquals("Entra-cert-pem", c.getId());
        assertEquals("tenant-guid", c.getTenantId());
        assertEquals("client-id", c.getClientId());
        assertEquals("scope1", c.getScopes());
        assertEquals("user@example.com", c.getUsername());
        assertEquals("https://login.microsoftonline.com", c.getAuthorityHost());
        assertEquals(PemFixtures.CERT_PEM, c.getCertificatePem());
        assertEquals(PemFixtures.KEY_PEM.trim(), Secret.toString(c.getPrivateKeyPem()).trim());
    }
}


