package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import hudson.Util;
import hudson.util.ComboBoxModel;
import hudson.util.FormValidation;
import org.kohsuke.stapler.QueryParameter;

public abstract class AbstractEntraCredentialsDescriptor extends CredentialsDescriptor {

    public static final String DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com";

    /**
     * Provides tenant ID suggestions.
     */
    ComboBoxModel doFillTenantIdItems() {
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

    @SuppressWarnings("unused")
    public FormValidation doCheckAuthorityHost(@QueryParameter String value) {
        if (Util.fixEmpty(value) == null) {
            return FormValidation.error(Messages.FormValidation_AuthorityHostRequired());
        }
        return FormValidation.ok();
    }

}
