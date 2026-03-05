package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeRequirement;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.util.Secret;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.jenkinsci.plugins.credentialsbinding.impl.SecretBuildWrapper;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.CaptureEnvironmentBuilder;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link EntraOAuthCredentialBinding}.
 */
public class EntraOAuthCredentialBindingTest {

    // -------------------------------------------------------------------------
    // Test doubles
    // -------------------------------------------------------------------------

    /**
     * Credentials stub that bypasses MSAL and returns a fixed token.
     */
    static class StubCredentials extends EntraOAuthCredentials {
        private final String fixedToken;
        private final boolean usernameIsSecret;

        StubCredentials(String id, String username, String fixedToken, boolean usernameIsSecret) {
            super(CredentialsScope.GLOBAL, id, null,
                    "tenant", "client",
                    new EntraClientSecretAuthMethod(Secret.fromString("stub-secret")),
                    "scope", username, null);
            this.fixedToken = fixedToken;
            this.usernameIsSecret = usernameIsSecret;
        }

        @Override
        public Secret getAccessToken(OAuth2ScopeRequirement requirement) {
            return Secret.fromString(fixedToken);
        }

        @Override
        public boolean isUsernameSecret() {
            return usernameIsSecret;
        }
    }

    private static CredentialsStore getStore(JenkinsRule jenkins) {
        for (CredentialsStore store : CredentialsProvider.lookupStores(jenkins.getInstance())) {
            return store;
        }
        throw new IllegalStateException("System credentials store not found.");
    }

    // -------------------------------------------------------------------------
    // Unit tests (no Jenkins required)
    // -------------------------------------------------------------------------

    @Test
    public void gettersReturnConstructorValues() {
        EntraOAuthCredentialBinding binding = new EntraOAuthCredentialBinding(
                "MY_USER", "MY_TOKEN", "cred-id");

        assertEquals("MY_USER", binding.getUsernameVariable());
        assertEquals("MY_TOKEN", binding.getTokenVariable());
        assertEquals("cred-id", binding.getCredentialsId());
    }

    @Test
    public void typeIsEntraOAuthCredentials() {
        EntraOAuthCredentialBinding binding = new EntraOAuthCredentialBinding(
                "U", "T", "id");
        assertEquals(EntraOAuthCredentials.class, binding.type());
    }

    @Test
    public void descriptorDoesNotRequireWorkspace() {
        assertFalse(new EntraOAuthCredentialBinding.DescriptorImpl().requiresWorkspace());
    }

    @Test
    public void descriptorHasNonBlankDisplayName() {
        String name = new EntraOAuthCredentialBinding.DescriptorImpl().getDisplayName();
        assertNotNull(name);
        assertFalse(name.isBlank());
    }

    @Test
    public void descriptorTypeIsEntraOAuthCredentials() {
        assertEquals(EntraOAuthCredentials.class,
                new EntraOAuthCredentialBinding.DescriptorImpl().type());
    }

    // -------------------------------------------------------------------------
    // Integration tests (@WithJenkins)
    // -------------------------------------------------------------------------

    @Test
    @WithJenkins
    public void bindInjectsUsernameAndTokenIntoEnvironment(JenkinsRule jenkins) throws Exception {
        getStore(jenkins).addCredentials(Domain.global(),
                new StubCredentials("cid", "alice", "tok-abc", false));

        CaptureEnvironmentBuilder capture = new CaptureEnvironmentBuilder();
        FreeStyleProject project = jenkins.createFreeStyleProject();
        project.getBuildWrappersList().add(new SecretBuildWrapper(List.of(
                new EntraOAuthCredentialBinding("USERNAME", "ACCESS_TOKEN",
                        "cid"))));
        project.getBuildersList().add(capture);

        jenkins.buildAndAssertSuccess(project);

        assertEquals("alice", capture.getEnvVars().get("USERNAME"));
        assertEquals("tok-abc", capture.getEnvVars().get("ACCESS_TOKEN"));
    }

    @Test
    @WithJenkins
    public void variablesIncludesUsernameWhenItIsSecret(JenkinsRule jenkins) throws Exception {
        getStore(jenkins).addCredentials(Domain.global(),
                new StubCredentials("cid-secret", "user", "tok", true));

        FreeStyleProject project = jenkins.createFreeStyleProject();
        EntraOAuthCredentialBinding binding = new EntraOAuthCredentialBinding(
                "MY_USER", "MY_TOKEN", "cid-secret");
        project.getBuildWrappersList().add(new SecretBuildWrapper(List.of(binding)));

        FreeStyleBuild build = jenkins.buildAndAssertSuccess(project);

        Set<String> vars = binding.variables(build);
        assertTrue(vars.contains("MY_USER"), "username should be in sensitive vars when isUsernameSecret");
        assertTrue(vars.contains("MY_TOKEN"), "token should always be in sensitive vars");
    }

    @Test
    @WithJenkins
    public void variablesExcludesUsernameWhenItIsNotSecret(JenkinsRule jenkins) throws Exception {
        getStore(jenkins).addCredentials(Domain.global(),
                new StubCredentials("cid-public", "user", "tok", false));

        FreeStyleProject project = jenkins.createFreeStyleProject();
        EntraOAuthCredentialBinding binding = new EntraOAuthCredentialBinding(
                "MY_USER", "MY_TOKEN", "cid-public");
        project.getBuildWrappersList().add(new SecretBuildWrapper(List.of(binding)));

        FreeStyleBuild build = jenkins.buildAndAssertSuccess(project);

        Set<String> vars = binding.variables(build);
        assertFalse(vars.contains("MY_USER"), "username should NOT be in sensitive vars when not secret");
        assertTrue(vars.contains("MY_TOKEN"), "token should always be in sensitive vars");
    }
}