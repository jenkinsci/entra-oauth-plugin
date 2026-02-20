package io.jenkins.plugins.entraoauth;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.IClientCredential;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

/**
 * Client-secret authentication method for Entra OAuth credentials.
 */
public class EntraClientSecretAuthMethod extends EntraAuthMethod {

    private final Secret clientSecret;

    @DataBoundConstructor
    public EntraClientSecretAuthMethod(@CheckForNull Secret clientSecret) {
        this.clientSecret = clientSecret;
    }

    @CheckForNull
    public Secret getClientSecret() {
        return clientSecret;
    }

    @Override
    protected IClientCredential createClientCredential() {
        String secret = Secret.toString(clientSecret);
        if (Util.fixEmptyAndTrim(secret) == null) {
            throw new IllegalArgumentException(Messages.FormValidation_ClientSecretRequired());
        }
        return ClientCredentialFactory.createFromSecret(secret);
    }

    @Extension
    @Symbol("entraClientSecretAuth")
    public static class DescriptorImpl extends Descriptor<EntraAuthMethod> {
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraClientSecretAuthMethod_DisplayName();
        }
    }
}
