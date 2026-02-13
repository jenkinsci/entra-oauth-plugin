package io.jenkins.plugins.entraoauth;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Util;
import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

final class PemUtils {
    private static final String CERT_BEGIN = "-----BEGIN CERTIFICATE-----";
    private static final String CERT_END = "-----END CERTIFICATE-----";
    private static final String KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String KEY_END = "-----END PRIVATE KEY-----";
    private static final String RSA_KEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";

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

    static PrivateKey parsePrivateKey(@CheckForNull String pem) throws Exception {
        String trimmed = Util.fixEmptyAndTrim(pem);
        if (trimmed == null) {
            throw new IllegalArgumentException(Messages.PemUtils_PrivateKeyPemRequired());
        }
        if (trimmed.contains(RSA_KEY_BEGIN)) {
            throw new IllegalArgumentException(Messages.PemUtils_Pkcs1RsaKeysNotSupportedUsePkcs8());
        }
        String base64 = stripPem(trimmed, KEY_BEGIN, KEY_END);
        byte[] der = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception ignored) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

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


