package io.jenkins.plugins.entraoauth;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.IClientCredential;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

/**
 * PEM-certificate authentication method for Entra OAuth credentials.
 */
public class EntraPemAuthMethod extends EntraAuthMethod {

    private final Secret certificatePem;
    private final Secret privateKeyPem;
    private final Secret privateKeyPassword;

    @DataBoundConstructor
    public EntraPemAuthMethod(
            @CheckForNull Secret certificatePem,
            @CheckForNull Secret privateKeyPem,
            @CheckForNull Secret privateKeyPassword) {
        this.certificatePem = certificatePem;
        this.privateKeyPem = privateKeyPem;
        this.privateKeyPassword = privateKeyPassword;
    }

    public Secret getCertificatePem() {
        return certificatePem;
    }

    public Secret getPrivateKeyPem() {
        return privateKeyPem;
    }

    public Secret getPrivateKeyPassword() {
        return privateKeyPassword;
    }

    @Override
    protected IClientCredential createClientCredential() throws Exception {
        return ClientCredentialFactory.createFromCertificate(
                PemUtils.parsePrivateKey(Secret.toString(privateKeyPem), Secret.toString(privateKeyPassword)),
                PemUtils.parseCertificate(Secret.toString(certificatePem)));
    }

    @Extension
    @Symbol("entraPemAuth")
    public static class DescriptorImpl extends Descriptor<EntraAuthMethod> {
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraPemAuthMethod_DisplayName();
        }

        @SuppressWarnings("unused")
        public FormValidation doCheckCertificatePem(@QueryParameter String value) {
            try {
                PemUtils.parseCertificate(value);
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error(Messages.FormValidation_ErrorWithDetail(e.getMessage()));
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_CertificatePemInvalid());
            }
        }

        @SuppressWarnings("unused")
        public FormValidation doCheckPrivateKeyPem(
                @QueryParameter String value, @QueryParameter Secret privateKeyPassword) {
            try {
                PemUtils.parsePrivateKey(value, Secret.toString(privateKeyPassword));
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error(Messages.FormValidation_ErrorWithDetail(e.getMessage()));
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_PrivateKeyPemInvalid());
            }
        }
    }
}
