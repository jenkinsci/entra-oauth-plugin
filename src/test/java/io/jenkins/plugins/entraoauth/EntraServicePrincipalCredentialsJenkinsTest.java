package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.security.ACL;
import hudson.util.ListBoxModel;
import java.util.Collections;
import java.util.List;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * JenkinsRule tests for Entra credentials.
 */
public class EntraServicePrincipalCredentialsJenkinsTest {

    @Rule
    public JenkinsRule jenkins = new JenkinsRule();

    /**
     * Verifies credentials can be stored and retrieved.
     */
    @Test
    public void credentialCanBeStoredAndRetrieved() throws Exception {
        EntraServicePrincipalCredentials credentials = new EntraClientSecretCredentials(
                com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL,
                "id",
                "desc",
                "tenant",
                "client",
                hudson.util.Secret.fromString("secret"),
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

        List<EntraServicePrincipalCredentials> all = CredentialsProvider.lookupCredentials(
                EntraServicePrincipalCredentials.class,
                jenkins.getInstance(),
                ACL.SYSTEM,
                Collections.emptyList());

        assertEquals(1, all.size());
        assertEquals("tenant", all.get(0).getTenantId());
    }

    /**
     * Verifies tenant ID suggestions are present.
     */
    @Test
    public void tenantIdItemsPresent() {
        EntraClientSecretCredentials.DescriptorImpl descriptor =
                (EntraClientSecretCredentials.DescriptorImpl)
                        jenkins.getInstance().getDescriptor(EntraClientSecretCredentials.class);

        ListBoxModel items = descriptor.doFillTenantIdItems();
        assertTrue(items.stream().anyMatch(item -> "organizations".equals(item.value)));
        assertTrue(items.stream().anyMatch(item -> "common".equals(item.value)));
        assertTrue(items.stream().anyMatch(item -> "consumers".equals(item.value)));
    }
}


