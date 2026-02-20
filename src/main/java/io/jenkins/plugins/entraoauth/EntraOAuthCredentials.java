package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeRequirement;
import com.google.jenkins.plugins.credentials.oauth.StandardUsernameOAuth2Credentials;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientCredential;
import com.microsoft.aad.msal4j.IConfidentialClientApplication;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.ComboBoxModel;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Microsoft Entra OAuth credentials with pluggable authentication methods.
 */
public class EntraOAuthCredentials extends BaseStandardCredentials
        implements StandardUsernameOAuth2Credentials<OAuth2ScopeRequirement> {

    public static final String DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com";

    private static final Logger LOGGER = Logger.getLogger(EntraOAuthCredentials.class.getName());

    private final String tenantId;
    private final String clientId;
    private final EntraAuthMethod authenticationMethod;
    private final String scopes;
    private final String username;
    private final String authorityHost;

    private transient volatile IConfidentialClientApplication application;

    @DataBoundConstructor
    public EntraOAuthCredentials(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @CheckForNull String tenantId,
            @CheckForNull String clientId,
            @CheckForNull EntraAuthMethod authenticationMethod,
            @CheckForNull String scopes,
            @CheckForNull String username,
            @CheckForNull String authorityHost) {
        super(scope, id == null ? "" : id, description);
        this.tenantId = Util.fixEmptyAndTrim(tenantId);
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.authenticationMethod = authenticationMethod;
        this.scopes = Util.fixEmptyAndTrim(scopes);
        this.username = Util.fixEmptyAndTrim(username);
        this.authorityHost = Util.fixEmptyAndTrim(authorityHost);
    }

    @NonNull
    public String getTenantId() {
        return tenantId == null ? "" : tenantId;
    }

    @NonNull
    public String getClientId() {
        return clientId == null ? "" : clientId;
    }

    @CheckForNull
    public EntraAuthMethod getAuthenticationMethod() {
        return authenticationMethod;
    }

    @NonNull
    public String getScopes() {
        return scopes == null ? "" : scopes;
    }

    @NonNull
    public String getUsername() {
        return username == null ? "" : username;
    }

    @NonNull
    public String getAuthorityHost() {
        String host = Util.fixEmptyAndTrim(authorityHost);
        if (host == null) {
            host = DEFAULT_AUTHORITY_HOST;
        }
        while (host.endsWith("/")) {
            host = host.substring(0, host.length() - 1);
        }
        return host;
    }

    @NonNull
    public List<String> getScopeList() {
        return ScopeUtils.parseScopes(getScopes());
    }

    @Override
    public Secret getAccessToken(OAuth2ScopeRequirement requirement) {
        Collection<String> requestedScopes = getScopesFromRequirement(requirement);
        if (requestedScopes.isEmpty()) {
            return null;
        }

        try {
            IConfidentialClientApplication app = getApplication();
            Set<String> scopeSet = new LinkedHashSet<>(requestedScopes);
            ClientCredentialParameters params = ClientCredentialParameters.builder(scopeSet).build();
            IAuthenticationResult result = app.acquireToken(params).get();
            if (result == null || result.accessToken() == null) {
                return null;
            }
            return Secret.fromString(result.accessToken());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.log(Level.WARNING, "Interrupted while acquiring Entra access token", e);
        } catch (ExecutionException e) {
            LOGGER.log(Level.WARNING, "Failed to acquire Entra access token", e);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Unable to acquire Entra access token", e);
        }
        return null;
    }

    private IClientCredential createClientCredential() throws Exception {
        if (authenticationMethod == null) {
            throw new IllegalArgumentException(Messages.FormValidation_AuthenticationMethodRequired());
        }
        return authenticationMethod.createClientCredential();
    }

    private Collection<String> getScopesFromRequirement(OAuth2ScopeRequirement requirement) {
        if (requirement != null && requirement.getScopes() != null && !requirement.getScopes().isEmpty()) {
            return requirement.getScopes();
        }
        return getScopeList();
    }

    private IConfidentialClientApplication getApplication() throws Exception {
        IConfidentialClientApplication local = application;
        if (local == null) {
            synchronized (this) {
                if (application == null) {
                    application = buildApplication();
                }
                local = application;
            }
        }
        return local;
    }

    private IConfidentialClientApplication buildApplication() throws Exception {
        IClientCredential credential = createClientCredential();
        String authority = getAuthorityHost() + "/" + getTenantId();
        return ConfidentialClientApplication.builder(getClientId(), credential)
                .authority(authority)
                .build();
    }

    @Extension
    @Symbol("entraOAuth")
    public static class DescriptorImpl extends CredentialsDescriptor {
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraOAuthCredentials_DisplayName();
        }

        /**
         * Provides tenant ID suggestions.
         */
        @SuppressWarnings("unused")
        public ComboBoxModel doFillTenantIdItems() {
            ComboBoxModel items = new ComboBoxModel();
            items.add("organizations");
            items.add("common");
            items.add("consumers");
            return items;
        }

        /**
         * Returns the default authority host.
         */
        @SuppressWarnings({"unused", "SameReturnValue"})
        public String getDefaultAuthorityHost() {
            return DEFAULT_AUTHORITY_HOST;
        }

        /**
         * Validates scopes input.
         */
        @SuppressWarnings("unused")
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
        @SuppressWarnings("unused")
        public FormValidation doTestConnection(
                @QueryParameter String tenantId,
                @QueryParameter String clientId,
                @QueryParameter String scopes,
                @QueryParameter String username,
                @QueryParameter String authorityHost,
                @QueryParameter("authenticationMethod.stapler-class") String authStaplerClass,
                @QueryParameter("authenticationMethod.$class") String authDollarClass,
                @QueryParameter Secret clientSecret,
                @QueryParameter Secret certificateBase64,
                @QueryParameter Secret certificatePassword,
                @QueryParameter Secret certificatePem,
                @QueryParameter Secret privateKeyPem,
                @QueryParameter Secret privateKeyPassword) {
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

            EntraAuthMethod authMethod = buildAuthMethod(
                    authStaplerClass,
                    authDollarClass,
                    clientSecret,
                    certificateBase64,
                    certificatePassword,
                    certificatePem,
                    privateKeyPem,
                    privateKeyPassword);
            if (authMethod == null) {
                return FormValidation.error(Messages.FormValidation_AuthenticationMethodRequired());
            }

            try {
                EntraOAuthCredentials credentials = new EntraOAuthCredentials(
                        CredentialsScope.SYSTEM,
                        "test",
                        null,
                        tenantId,
                        clientId,
                        authMethod,
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

        private static EntraAuthMethod buildAuthMethod(
                String authStaplerClass,
                String authDollarClass,
                Secret clientSecret,
                Secret certificateBase64,
                Secret certificatePassword,
                Secret certificatePem,
                Secret privateKeyPem,
                Secret privateKeyPassword) {
            String discriminator = Util.fixEmptyAndTrim(authStaplerClass);
            if (discriminator == null) {
                discriminator = Util.fixEmptyAndTrim(authDollarClass);
            }
            if (discriminator != null) {
                if (discriminator.endsWith("EntraClientSecretAuthMethod")) {
                    return new EntraClientSecretAuthMethod(clientSecret);
                }
                if (discriminator.endsWith("EntraPfxAuthMethod")) {
                    return new EntraPfxAuthMethod(certificateBase64, certificatePassword);
                }
                if (discriminator.endsWith("EntraPemAuthMethod")) {
                    return new EntraPemAuthMethod(certificatePem, privateKeyPem, privateKeyPassword);
                }
            }

            if (Util.fixEmptyAndTrim(Secret.toString(clientSecret)) != null) {
                return new EntraClientSecretAuthMethod(clientSecret);
            }
            if (Util.fixEmptyAndTrim(Secret.toString(certificateBase64)) != null) {
                return new EntraPfxAuthMethod(certificateBase64, certificatePassword);
            }
            if (Util.fixEmptyAndTrim(Secret.toString(certificatePem)) != null
                    || Util.fixEmptyAndTrim(Secret.toString(privateKeyPem)) != null) {
                return new EntraPemAuthMethod(certificatePem, privateKeyPem, privateKeyPassword);
            }
            return null;
        }
    }
}
