package io.jenkins.plugins.entraoauth;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Util;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

final class PemUtils {
    private static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----";
    private static final String CERT_END = "-----END CERTIFICATE-----";
    private static final String KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";

    private PemUtils() {}

    static byte[] decodeBase64(@CheckForNull String value) {
        String trimmed = Util.fixEmptyAndTrim(value);
        if (trimmed == null) {
            throw new IllegalArgumentException(Messages.PemUtils_CertificateDataRequired());
        }
        String normalized = trimmed.replaceAll("\\s+", "");
        return Base64.getDecoder().decode(normalized);
    }

    static X509Certificate parseCertificate(@CheckForNull String pem) throws Exception {
        String trimmed = Util.fixEmptyAndTrim(pem);
        if (trimmed == null) {
            throw new IllegalArgumentException(Messages.PemUtils_CertificatePemRequired());
        }
        String base64 = stripPem(trimmed, CERT_BEGIN, CERT_END);
        byte[] der = Base64.getDecoder().decode(base64);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        Certificate cert = factory.generateCertificate(new ByteArrayInputStream(der));
        if (!(cert instanceof X509Certificate)) {
            throw new IllegalArgumentException(Messages.PemUtils_CertificatePemMustBeX509());
        }
        return (X509Certificate) cert;
    }

    static PrivateKey parsePrivateKey(@CheckForNull String pem) {
        return parsePrivateKey(pem, null);
    }

    static PrivateKey parsePrivateKey(@CheckForNull String pem, @CheckForNull String password) {
        String trimmed = Util.fixEmptyAndTrim(pem);
        if (trimmed == null) {
            throw new IllegalArgumentException(Messages.PemUtils_PrivateKeyPemRequired());
        }
        if (!trimmed.contains(KEY_BEGIN)
                && !trimmed.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                && !trimmed.contains("-----BEGIN RSA PRIVATE KEY-----")
                && !trimmed.contains("-----BEGIN EC PRIVATE KEY-----")) {
            throw new IllegalArgumentException(Messages.PemUtils_PemHeaderOrFooterMissing());
        }

        try (PEMParser parser = new PEMParser(new StringReader(trimmed))) {
            Object parsed = parser.readObject();
            if (parsed == null) {
                throw new IllegalArgumentException(Messages.PemUtils_PemHeaderOrFooterMissing());
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (parsed instanceof PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) {
                return converter.getPrivateKey(decryptPkcs8PrivateKey(encryptedPrivateKeyInfo, password));
            }
            if (parsed instanceof PEMEncryptedKeyPair encryptedKeyPair) {
                return converter.getKeyPair(decryptPemKeyPair(encryptedKeyPair, password)).getPrivate();
            }
            if (parsed instanceof PrivateKeyInfo privateKeyInfo) {
                return converter.getPrivateKey(privateKeyInfo);
            }
            if (parsed instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }

            throw new IllegalArgumentException(Messages.FormValidation_PrivateKeyPemInvalid());
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException(Messages.PemUtils_PrivateKeyPemCouldNotBeDecrypted(), e);
        }
    }

    private static PrivateKeyInfo decryptPkcs8PrivateKey(
            PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, @CheckForNull String password) throws Exception {
        char[] passphrase = getRequiredPassword(password);
        InputDecryptorProvider decryptorProvider =
                new JceOpenSSLPKCS8DecryptorProviderBuilder().build(passphrase);
        return encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider);
    }

    private static PEMKeyPair decryptPemKeyPair(PEMEncryptedKeyPair encryptedKeyPair, @CheckForNull String password)
            throws Exception {
        char[] passphrase = getRequiredPassword(password);
        PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(passphrase);
        return encryptedKeyPair.decryptKeyPair(decryptorProvider);
    }

    private static char[] getRequiredPassword(@CheckForNull String password) {
        String trimmed = Util.fixEmptyAndTrim(password);
        if (trimmed == null) {
            throw new IllegalArgumentException(Messages.PemUtils_PrivateKeyPasswordRequiredForEncryptedKey());
        }
        return trimmed.toCharArray();
    }

    @SuppressWarnings("SameParameterValue")
    private static String stripPem(String pem, String begin, String end) {
        int start = pem.indexOf(begin);
        int stop = pem.indexOf(end);
        if (start < 0 || stop < 0 || stop <= start) {
            throw new IllegalArgumentException(Messages.PemUtils_PemHeaderOrFooterMissing());
        }
        String body = pem.substring(start + begin.length(), stop);
        return body.replaceAll("\\s+", "");
    }
}
