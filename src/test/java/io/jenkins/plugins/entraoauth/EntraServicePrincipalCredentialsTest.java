package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsScope;
import hudson.util.Secret;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

    /**
     * Verifies encrypted PKCS#8 PEM private key parsing when a password is provided.
     */
    @Test
    public void pemPrivateKeyParsingSupportsEncryptedPkcs8() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        String password = "changeit";
        String pem = toEncryptedPkcs8Pem(privateKey, password);

        PrivateKey parsed = PemUtils.parsePrivateKey(pem, password);
        assertEquals(privateKey.getAlgorithm(), parsed.getAlgorithm());
    }

    /**
     * Verifies encrypted PEM private keys fail validation without a password.
     */
    @Test
    public void pemPrivateKeyParsingEncryptedPkcs8RequiresPassword() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String pem = toEncryptedPkcs8Pem(keyPair.getPrivate(), "changeit");

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> PemUtils.parsePrivateKey(pem));
        assertEquals(Messages.PemUtils_PrivateKeyPasswordRequiredForEncryptedKey(), ex.getMessage());
    }

    @SuppressWarnings("SameParameterValue")
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

    private static String toEncryptedPkcs8Pem(PrivateKey privateKey, String password) throws Exception {
        JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder =
                new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
        encryptorBuilder.setPassword(password.toCharArray());
        OutputEncryptor encryptor = encryptorBuilder.build();
        JcaPKCS8Generator generator = new JcaPKCS8Generator(privateKey, encryptor);

        StringWriter output = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(output)) {
            writer.writeObject(generator.generate());
        }
        return output.toString();
    }
}
