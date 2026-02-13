package io.jenkins.plugins.entraoauth;

import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeRequirement;
import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Entra-specific OAuth2 scope requirement.
 */
public class EntraOAuth2ScopeRequirement extends OAuth2ScopeRequirement {
    private final Collection<String> scopes;

    /**
     * Creates a scope requirement with the provided scopes.
     */
    @DataBoundConstructor
    public EntraOAuth2ScopeRequirement(@NonNull Collection<String> scopes) {
        this.scopes = scopes;
    }

    /**
     * Returns required scopes.
     */
    @Override
    public Collection<String> getScopes() {
        return Collections.unmodifiableCollection(scopes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        EntraOAuth2ScopeRequirement that = (EntraOAuth2ScopeRequirement) o;
        return Objects.equals(scopes, that.scopes);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return Objects.hash(scopes);
    }
}


