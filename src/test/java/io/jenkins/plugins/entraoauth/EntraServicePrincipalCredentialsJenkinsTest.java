package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.security.ACL;
import hudson.util.ComboBoxModel;
import hudson.util.Secret;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Jenkins integration tests for Entra credentials.
 */
@WithJenkins
public class EntraServicePrincipalCredentialsJenkinsTest {

    /**
     * Verifies credentials can be stored and retrieved.
     */
    @Test
    public void credentialCanBeStoredAndRetrieved(JenkinsRule jenkins) throws Exception {
        EntraOAuthCredentials credentials = new EntraOAuthCredentials(
                com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL,
                "id",
                "desc",
                "tenant",
                "client",
                new EntraClientSecretAuthMethod(Secret.fromString("secret")),
                "scope1",
                "user",
                null);

        CredentialsStore store = null;
        for (CredentialsStore candidate : CredentialsProvider.lookupStores(jenkins.getInstance())) {
            store = candidate;
            break;
        }
        if (store == null) {
            throw new IllegalStateException("System credentials store not found.");
        }
        store.addCredentials(Domain.global(), credentials);

        List<EntraOAuthCredentials> all = CredentialsProvider.lookupCredentialsInItemGroup(
                EntraOAuthCredentials.class,
                jenkins.getInstance(),
                ACL.SYSTEM2,
                Collections.emptyList());

        assertEquals(1, all.size());
        assertEquals("tenant", all.get(0).getTenantId());
        assertTrue(all.get(0).getAuthenticationMethod() instanceof EntraClientSecretAuthMethod);
    }

    /**
     * Verifies tenant ID suggestions are present.
     */
    @Test
    public void tenantIdItemsPresent(JenkinsRule jenkins) {
        EntraOAuthCredentials.DescriptorImpl descriptor =
                (EntraOAuthCredentials.DescriptorImpl) jenkins.getInstance().getDescriptor(EntraOAuthCredentials.class);

        assertNotNull(descriptor);
        ComboBoxModel items = descriptor.doFillTenantIdItems();
        assertTrue(items.stream().anyMatch("organizations"::equals));
        assertTrue(items.stream().anyMatch("common"::equals));
        assertTrue(items.stream().anyMatch("consumers"::equals));
    }
}
