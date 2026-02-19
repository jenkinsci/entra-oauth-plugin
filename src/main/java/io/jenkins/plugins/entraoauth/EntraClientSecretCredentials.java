package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.IClientCredential;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
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
    public static class DescriptorImpl extends AbstractEntraCredentialsDescriptor {
        /**
         * Returns the display name for this credential type.
         */
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraClientSecretCredentials_DisplayName();
        }

        /**
         * Tests token acquisition with the provided settings.
         */
        @RequirePOST
        @SuppressWarnings("unused")
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
