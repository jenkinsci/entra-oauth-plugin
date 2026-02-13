package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.IClientCredential;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import java.io.ByteArrayInputStream;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Entra PFX certificate based service principal credentials.
 */
public class EntraCertificatePfxCredentials extends EntraServicePrincipalCredentials {

    private final Secret certificateBase64;
    private final Secret certificatePassword;

    /**
     * Creates PFX certificate credentials.
     */
    @DataBoundConstructor
    public EntraCertificatePfxCredentials(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @CheckForNull String tenantId,
            @CheckForNull String clientId,
            @CheckForNull Secret certificateBase64,
            @CheckForNull Secret certificatePassword,
            @CheckForNull String scopes,
            @CheckForNull String username,
            @CheckForNull String authorityHost) {
        super(scope, id, description, tenantId, clientId, scopes, username, authorityHost);
        this.certificateBase64 = certificateBase64;
        this.certificatePassword = certificatePassword;
    }

    /**
     * Returns the base64-encoded PFX content.
     */
    public Secret getCertificateBase64() {
        return certificateBase64;
    }

    /**
     * Returns the PFX password, if set.
     */
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
    @Symbol("entraCertPfx")
    public static class DescriptorImpl extends CredentialsDescriptor {
        /**
         * Returns the display name for this credential type.
         */
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraCertificatePfxCredentials_DisplayName();
        }

        /**
         * Provides tenant ID suggestions.
         */
        public ListBoxModel doFillTenantIdItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("organizations");
            items.add("common");
            items.add("consumers");
            return items;
        }

        /**
         * Returns the default authority host.
         */
        public String getDefaultAuthorityHost() {
            return defaultAuthorityHost();
        }

        /**
         * Validates tenant ID input.
         */
        public FormValidation doCheckTenantId(@QueryParameter String value) {
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.FormValidation_TenantIdRequired());
            }
            return FormValidation.ok();
        }

        /**
         * Validates client ID input.
         */
        public FormValidation doCheckClientId(@QueryParameter String value) {
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.FormValidation_ClientIdRequired());
            }
            return FormValidation.ok();
        }

        /**
         * Validates base64 PFX input.
         */
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

        /**
         * Validates scopes input.
         */
        public FormValidation doCheckScopes(@QueryParameter String value) {
            if (ScopeUtils.parseScopes(value).isEmpty()) {
                return FormValidation.error(Messages.FormValidation_ScopesRequired());
            }
            return FormValidation.ok();
        }

        /**
         * Tests token acquisition with the provided settings.
         */
        @RequirePOST
        public FormValidation doTestConnection(
                @QueryParameter String tenantId,
                @QueryParameter String clientId,
                @QueryParameter Secret certificateBase64,
                @QueryParameter Secret certificatePassword,
                @QueryParameter String scopes,
                @QueryParameter String username,
                @QueryParameter String authorityHost) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);

            if (Util.fixEmptyAndTrim(tenantId) == null) {
                return FormValidation.error(Messages.FormValidation_TenantIdRequired());
            }
            if (Util.fixEmptyAndTrim(clientId) == null) {
                return FormValidation.error(Messages.FormValidation_ClientIdRequired());
            }
            if (ScopeUtils.parseScopes(scopes).isEmpty()) {
                return FormValidation.error(Messages.FormValidation_ScopesRequired());
            }

            try {
                EntraCertificatePfxCredentials credentials = new EntraCertificatePfxCredentials(
                        CredentialsScope.SYSTEM,
                        "test",
                        null,
                        tenantId,
                        clientId,
                        certificateBase64,
                        certificatePassword,
                        scopes,
                        username,
                        authorityHost);
                Secret token =
                        credentials.getAccessToken(new EntraOAuth2ScopeRequirement(ScopeUtils.parseScopes(scopes)));
                if (token == null || Util.fixEmptyAndTrim(token.getPlainText()) == null) {
                    return FormValidation.error(Messages.FormValidation_TestTokenFailed());
                }
                return FormValidation.ok(Messages.FormValidation_TestTokenSuccess());
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_TestTokenErrorWithDetail(e.getMessage()));
            }
        }
    }
}
