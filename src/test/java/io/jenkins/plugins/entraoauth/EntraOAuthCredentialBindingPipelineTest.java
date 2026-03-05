package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.google.jenkins.plugins.credentials.oauth.OAuth2ScopeRequirement;
import hudson.model.Result;
import hudson.util.Secret;
import java.util.Collection;
import java.util.List;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pipeline integration tests for {@link EntraOAuthCredentialBinding}.
 */
@WithJenkins
public class EntraOAuthCredentialBindingPipelineTest {

    // -------------------------------------------------------------------------
    // Test doubles
    // -------------------------------------------------------------------------

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
    // Tests
    // -------------------------------------------------------------------------

    /**
     * Verifies that the {@code entraOAuth2} symbol works in pipeline Groovy syntax
     * and that env vars are visible inside the {@code withCredentials} block.
     * The username is marked non-secret so its value appears unmasked in the log.
     */
    @Test
    public void withCredentialsStepBindsEnvVars(JenkinsRule jenkins) throws Exception {
        getStore(jenkins).addCredentials(Domain.global(),
                new StubCredentials("cid", "alice", "tok-abc", false));

        WorkflowJob project = jenkins.createProject(WorkflowJob.class);
        project.setDefinition(new CpsFlowDefinition(
                "node {\n"
                + "    withCredentials([entraOAuth2(\n"
                + "        credentialsId: 'cid',\n"
                + "        usernameVariable: 'USERNAME',\n"
                + "        tokenVariable: 'TOKEN'\n"
                + "    )]) {\n"
                + "        echo \"user=${env.USERNAME}\"\n"
                + "    }\n"
                + "}", true));

        WorkflowRun run = jenkins.buildAndAssertSuccess(project);
        jenkins.assertLogContains("user=alice", run);
    }

    /**
     * Verifies that referencing a non-existent credentials ID fails the build.
     */
    @Test
    public void missingCredentialFailsBuild(JenkinsRule jenkins) throws Exception {
        WorkflowJob project = jenkins.createProject(WorkflowJob.class);
        project.setDefinition(new CpsFlowDefinition(
                "node {\n"
                + "    withCredentials([entraOAuth2(\n"
                + "        credentialsId: 'does-not-exist',\n"
                + "        usernameVariable: 'U',\n"
                + "        tokenVariable: 'T'\n"
                + "    )]) {\n"
                + "        echo 'should not reach here'\n"
                + "    }\n"
                + "}", true));

        jenkins.buildAndAssertStatus(Result.FAILURE, project);
    }

    /**
     * Verifies that a secret username is masked in the build log.
     */
    @Test
    public void secretUsernameIsMaskedInLog(JenkinsRule jenkins) throws Exception {
        getStore(jenkins).addCredentials(Domain.global(),
                new StubCredentials("cid-secret", "supersecretuser", "tok", true));

        WorkflowJob project = jenkins.createProject(WorkflowJob.class);
        project.setDefinition(new CpsFlowDefinition(
                "node {\n"
                + "    withCredentials([entraOAuth2(\n"
                + "        credentialsId: 'cid-secret',\n"
                + "        usernameVariable: 'USERNAME',\n"
                + "        tokenVariable: 'TOKEN'\n"
                + "    )]) {\n"
                + "        echo env.USERNAME\n"
                + "    }\n"
                + "}", true));

        WorkflowRun run = jenkins.buildAndAssertSuccess(project);
        jenkins.assertLogNotContains("supersecretuser", run);
    }
}