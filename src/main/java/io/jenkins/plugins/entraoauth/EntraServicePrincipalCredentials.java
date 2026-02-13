package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsScope;
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
import hudson.Util;
import hudson.util.Secret;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Base class for Microsoft Entra service principal OAuth credentials.
 */
public abstract class EntraServicePrincipalCredentials extends BaseStandardCredentials
        implements StandardUsernameOAuth2Credentials<OAuth2ScopeRequirement> {

    private static final Logger LOGGER = Logger.getLogger(EntraServicePrincipalCredentials.class.getName());
    private static final String DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com";

    private final String tenantId;
    private final String clientId;
    private final String scopes;
    private final String username;
    private final String authorityHost;

    private transient volatile IConfidentialClientApplication application;

    protected EntraServicePrincipalCredentials(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @CheckForNull String tenantId,
            @CheckForNull String clientId,
            @CheckForNull String scopes,
            @CheckForNull String username,
            @CheckForNull String authorityHost) {
        super(scope, id == null ? "" : id, description);
        this.tenantId = Util.fixEmptyAndTrim(tenantId);
        this.clientId = Util.fixEmptyAndTrim(clientId);
        this.scopes = Util.fixEmptyAndTrim(scopes);
        this.username = Util.fixEmptyAndTrim(username);
        this.authorityHost = Util.fixEmptyAndTrim(authorityHost);
    }

    /**
     * Returns the tenant ID or tenant alias.
     */
    @NonNull
    public String getTenantId() {
        return tenantId == null ? "" : tenantId;
    }

    /**
     * Returns the client (application) ID.
     */
    @NonNull
    public String getClientId() {
        return clientId == null ? "" : clientId;
    }

    /**
     * Returns the configured scopes string.
     */
    @NonNull
    public String getScopes() {
        return scopes == null ? "" : scopes;
    }

    /**
     * Returns the username used by callers (not for Entra auth).
     */
    @NonNull
    public String getUsername() {
        return username == null ? "" : username;
    }

    /**
     * Returns the Entra authority host, with trailing slashes removed.
     */
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

    /**
     * Returns the configured scopes as a list.
     */
    @NonNull
    public List<String> getScopeList() {
        return ScopeUtils.parseScopes(getScopes());
    }

    /**
     * Retrieves an access token for the requested scopes.
     */
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

    protected abstract IClientCredential createClientCredential() throws Exception;

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

    protected static void validateRequired(String value, String field, java.util.function.Consumer<String> err) {
        if (Util.fixEmptyAndTrim(value) == null) {
            err.accept(field + " is required.");
        }
    }

    protected static String defaultAuthorityHost() {
        return DEFAULT_AUTHORITY_HOST;
    }
}


