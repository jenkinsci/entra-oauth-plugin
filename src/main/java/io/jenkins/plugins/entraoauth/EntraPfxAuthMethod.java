package io.jenkins.plugins.entraoauth;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.IClientCredential;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.ByteArrayInputStream;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

/**
 * PFX-certificate authentication method for Entra OAuth credentials.
 */
public class EntraPfxAuthMethod extends EntraAuthMethod {

    private final Secret certificateBase64;
    private final Secret certificatePassword;

    @DataBoundConstructor
    public EntraPfxAuthMethod(@CheckForNull Secret certificateBase64, @CheckForNull Secret certificatePassword) {
        this.certificateBase64 = certificateBase64;
        this.certificatePassword = certificatePassword;
    }

    public Secret getCertificateBase64() {
        return certificateBase64;
    }

    public Secret getCertificatePassword() {
        return certificatePassword;
    }

    @Override
    protected IClientCredential createClientCredential() throws Exception {
        byte[] bytes = PemUtils.decodeBase64(Secret.toString(certificateBase64));
        String password = Secret.toString(certificatePassword);
        return ClientCredentialFactory.createFromCertificate(new ByteArrayInputStream(bytes), password);
    }

    @Extension
    @Symbol("entraPfxAuth")
    public static class DescriptorImpl extends Descriptor<EntraAuthMethod> {
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraPfxAuthMethod_DisplayName();
        }

        @SuppressWarnings("unused")
        public FormValidation doCheckCertificateBase64(@QueryParameter String value) {
            try {
                PemUtils.decodeBase64(value);
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error(Messages.FormValidation_ErrorWithDetail(e.getMessage()));
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_CertificateBase64Invalid());
            }
        }
    }
}
