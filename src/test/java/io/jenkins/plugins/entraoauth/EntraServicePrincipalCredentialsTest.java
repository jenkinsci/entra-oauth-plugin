package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.util.Secret;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Unit tests for Entra credential parsing behavior.
 */
public class EntraServicePrincipalCredentialsTest {

    /**
     * Verifies defaults and scope parsing.
     */
    @Test
    public void defaultsAndScopeParsing() {
        EntraServicePrincipalCredentials credentials = new EntraClientSecretCredentials(
                CredentialsScope.GLOBAL,
                "id",
                "desc",
                "tenant",
                "client",
                Secret.fromString("secret"),
                "scope1, scope2\nscope3",
                "user",
                "https://login.microsoftonline.com/");

        assertEquals("https://login.microsoftonline.com", credentials.getAuthorityHost());
        assertEquals(List.of("scope1", "scope2", "scope3"), credentials.getScopeList());
    }

    /**
     * Verifies PKCS#8 PEM private key parsing.
     */
    @Test
    public void pemPrivateKeyParsingSupportsPkcs8() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        String pem = toPem("PRIVATE KEY", privateKey.getEncoded());

        PrivateKey parsed = PemUtils.parsePrivateKey(pem);
        assertEquals(privateKey.getAlgorithm(), parsed.getAlgorithm());
    }

    private static String toPem(String type, byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        StringBuilder builder = new StringBuilder();
        builder.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < encoded.length(); i += 64) {
            int end = Math.min(encoded.length(), i + 64);
            builder.append(encoded, i, end).append("\n");
        }
        builder.append("-----END ").append(type).append("-----");
        return builder.toString();
    }
}


