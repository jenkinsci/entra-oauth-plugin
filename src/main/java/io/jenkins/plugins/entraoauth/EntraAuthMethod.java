package io.jenkins.plugins.entraoauth;

import com.microsoft.aad.msal4j.IClientCredential;
import hudson.model.Describable;

/**
 * Base class for Entra authentication method variants.
 */
public abstract class EntraAuthMethod implements Describable<EntraAuthMethod> {

    /**
     * Creates an MSAL client credential for this authentication method.
     */
    protected abstract IClientCredential createClientCredential() throws Exception;
}
