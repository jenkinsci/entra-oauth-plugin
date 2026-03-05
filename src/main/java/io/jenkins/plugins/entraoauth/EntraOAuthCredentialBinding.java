package io.jenkins.plugins.entraoauth;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.credentialsbinding.BindingDescriptor;
import org.jenkinsci.plugins.credentialsbinding.MultiBinding;
import org.jenkinsci.plugins.credentialsbinding.impl.CredentialNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.IOException;
import java.util.*;

public class EntraOAuthCredentialBinding extends MultiBinding<EntraOAuthCredentials> {
    private final String usernameVariable;
    private final String tokenVariable;

    @DataBoundConstructor
    public EntraOAuthCredentialBinding(String usernameVariable, String tokenVariable, String credentialsId) {
        super(credentialsId);
        this.usernameVariable = usernameVariable;
        this.tokenVariable = tokenVariable;
    }

    public String getUsernameVariable() {
        return usernameVariable;
    }

    public String getTokenVariable() {
        return tokenVariable;
    }

    @Override
    protected Class<EntraOAuthCredentials> type() {
        return EntraOAuthCredentials.class;
    }

    @Override public MultiEnvironment bind(@NonNull Run<?, ?> build,
                                           @Nullable FilePath workspace,
                                           @Nullable Launcher launcher,
                                           @NonNull TaskListener listener) throws IOException, InterruptedException {
        EntraOAuthCredentials credentials = getCredentials(build);
        Map<String, String> secretValues = new LinkedHashMap<>();
        Map<String, String> publicValues = new LinkedHashMap<>();
        (credentials.isUsernameSecret() ? secretValues : publicValues).put(usernameVariable, credentials.getUsername());
        EntraOAuth2ScopeRequirement requirement = new EntraOAuth2ScopeRequirement(credentials.getScopeList());
        secretValues.put(tokenVariable, credentials.getAccessToken(requirement).getPlainText());
        return new MultiEnvironment(secretValues, publicValues);
    }

    @Override public Set<String> variables(@NonNull Run<?, ?> build) throws CredentialNotFoundException {
        EntraOAuthCredentials credentials = getCredentials(build);
        Set<String> vars = new LinkedHashSet<>();
        if (credentials.isUsernameSecret()) {
            vars.add(usernameVariable);
        }
        vars.add(tokenVariable);
        return vars;
    }

    @Symbol("entraOAuth2")
    @Extension
    public static class DescriptorImpl extends BindingDescriptor<EntraOAuthCredentials> {

        @Override protected Class<EntraOAuthCredentials> type() {
            return EntraOAuthCredentials.class;
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.EntraOAuthMultiBinding_UsernameAndToken();
        }

        @Override public boolean requiresWorkspace() {
            return false;
        }
    }
}
