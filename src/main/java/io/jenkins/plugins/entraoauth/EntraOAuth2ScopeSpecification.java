package io.jenkins.plugins.entraoauth;

import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeSpecification;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Entra-specific OAuth2 scope specification for credential domains.
 */
@SuppressWarnings("unused")
public class EntraOAuth2ScopeSpecification extends OAuth2ScopeSpecification<EntraOAuth2ScopeRequirement> {
    private final String specifiedScopesText;

    /**
     * Creates a specification from a raw scopes string.
     */
    @DataBoundConstructor
    public EntraOAuth2ScopeSpecification(String specifiedScopesText) {
        super(ScopeUtils.parseScopes(specifiedScopesText));
        this.specifiedScopesText = specifiedScopesText;
    }

    /**
     * Returns the raw scopes text used for configuration.
     */
    public String getSpecifiedScopesText() {
        return specifiedScopesText;
    }

    @Extension
    public static class DescriptorImpl extends OAuth2ScopeSpecification.Descriptor<EntraOAuth2ScopeRequirement> {
        public DescriptorImpl() {
            super(EntraOAuth2ScopeRequirement.class);
        }

        /**
         * Returns the display name for this specification type.
         */
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraOAuth2ScopeSpecification_DisplayName();
        }
    }
}


