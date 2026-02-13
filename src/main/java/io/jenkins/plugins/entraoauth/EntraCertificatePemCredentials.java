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
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Entra PEM certificate based service principal credentials.
 */
public class EntraCertificatePemCredentials extends EntraServicePrincipalCredentials {

    private final String certificatePem;
    private final Secret privateKeyPem;

    /**
     * Creates PEM certificate credentials.
     */
    @DataBoundConstructor
    public EntraCertificatePemCredentials(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @CheckForNull String tenantId,
            @CheckForNull String clientId,
            @CheckForNull String certificatePem,
            @CheckForNull Secret privateKeyPem,
            @CheckForNull String scopes,
            @CheckForNull String username,
            @CheckForNull String authorityHost) {
        super(scope, id, description, tenantId, clientId, scopes, username, authorityHost);
        this.certificatePem = Util.fixEmptyAndTrim(certificatePem);
        this.privateKeyPem = privateKeyPem;
    }

    /**
     * Returns the PEM-encoded certificate.
     */
    public String getCertificatePem() {
        return certificatePem == null ? "" : certificatePem;
    }

    /**
     * Returns the PEM-encoded private key.
     */
    public Secret getPrivateKeyPem() {
        return privateKeyPem;
    }

    @Override
    protected IClientCredential createClientCredential() throws Exception {
        return ClientCredentialFactory.createFromCertificate(
                PemUtils.parsePrivateKey(Secret.toString(privateKeyPem)),
                PemUtils.parseCertificate(certificatePem));
    }

    @Extension
    @Symbol("entraCertPem")
    public static class DescriptorImpl extends CredentialsDescriptor {
        /**
         * Returns the display name for this credential type.
         */
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraCertificatePemCredentials_DisplayName();
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
         * Validates certificate PEM input.
         */
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

        /**
         * Validates private key PEM input.
         */
        public FormValidation doCheckPrivateKeyPem(@QueryParameter String value) {
            try {
                PemUtils.parsePrivateKey(value);
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error(Messages.FormValidation_ErrorWithDetail(e.getMessage()));
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_PrivateKeyPemInvalid());
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
                @QueryParameter String certificatePem,
                @QueryParameter Secret privateKeyPem,
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
                EntraCertificatePemCredentials credentials = new EntraCertificatePemCredentials(
                        CredentialsScope.SYSTEM,
                        "test",
                        null,
                        tenantId,
                        clientId,
                        certificatePem,
                        privateKeyPem,
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
