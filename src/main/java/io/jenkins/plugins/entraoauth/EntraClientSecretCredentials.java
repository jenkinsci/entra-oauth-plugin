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
 * Entra client-secret based service principal credentials.
 */
public class EntraClientSecretCredentials extends EntraServicePrincipalCredentials {

    private final Secret clientSecret;

    /**
     * Creates client-secret credentials.
     */
    @DataBoundConstructor
    public EntraClientSecretCredentials(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @CheckForNull String tenantId,
            @CheckForNull String clientId,
            @CheckForNull Secret clientSecret,
            @CheckForNull String scopes,
            @CheckForNull String username,
            @CheckForNull String authorityHost) {
        super(scope, id, description, tenantId, clientId, scopes, username, authorityHost);
        this.clientSecret = clientSecret;
    }

    /**
     * Returns the client secret.
     */
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
    @Symbol("entraClientSecret")
    public static class DescriptorImpl extends CredentialsDescriptor {
        /**
         * Returns the display name for this credential type.
         */
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.entraClientSecretCredentials_DisplayName();
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
         * Validates client secret input.
         */
        public FormValidation doCheckClientSecret(@QueryParameter String value) {
            if (Util.fixEmptyAndTrim(value) == null) {
                return FormValidation.error(Messages.FormValidation_ClientSecretRequired());
            }
            return FormValidation.ok();
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
                @QueryParameter Secret clientSecret,
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
            if (Util.fixEmptyAndTrim(Secret.toString(clientSecret)) == null) {
                return FormValidation.error(Messages.FormValidation_ClientSecretRequired());
            }
            if (ScopeUtils.parseScopes(scopes).isEmpty()) {
                return FormValidation.error(Messages.FormValidation_ScopesRequired());
            }

            try {
                EntraClientSecretCredentials credentials = new EntraClientSecretCredentials(
                        CredentialsScope.SYSTEM,
                        "test",
                        null,
                        tenantId,
                        clientId,
                        clientSecret,
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
