package io.jenkins.plugins.entraoauth;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.IClientCredential;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Entra PEM certificate based service principal credentials.
 */
public class EntraCertificatePemCredentials extends EntraServicePrincipalCredentials {

    private final Secret certificatePem;
    private final Secret privateKeyPem;
    private final Secret privateKeyPassword;

    /**
     * Creates PEM certificate credentials.
     */
    @DataBoundConstructor
    public EntraCertificatePemCredentials(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @CheckForNull String tenantId,
            @CheckForNull String clientId,
            @CheckForNull Secret certificatePem,
            @CheckForNull Secret privateKeyPem,
            @CheckForNull Secret privateKeyPassword,
            @CheckForNull String scopes,
            @CheckForNull String username,
            @CheckForNull String authorityHost) {
        super(scope, id, description, tenantId, clientId, scopes, username, authorityHost);
        this.certificatePem = certificatePem;
        this.privateKeyPem = privateKeyPem;
        this.privateKeyPassword = privateKeyPassword;
    }

    /**
     * Returns the PEM-encoded certificate.
     */
    public Secret getCertificatePem() {
        return certificatePem;
    }

    /**
     * Returns the PEM-encoded private key.
     */
    public Secret getPrivateKeyPem() {
        return privateKeyPem;
    }

    /**
     * Returns the password for the private key.
     */
    public Secret getPrivateKeyPassword() { return privateKeyPassword; }

    @Override
    protected IClientCredential createClientCredential() throws Exception {
        return ClientCredentialFactory.createFromCertificate(
                PemUtils.parsePrivateKey(Secret.toString(privateKeyPem), Secret.toString(privateKeyPassword)),
                PemUtils.parseCertificate(Secret.toString(certificatePem)));
    }

    @Extension
    @Symbol("entraCertPem")
    @SuppressWarnings("unused")
    public static class DescriptorImpl extends AbstractEntraCredentialsDescriptor {
        /**
         * Returns the display name for this credential type.
         */
        @Override
        @NonNull
        public String getDisplayName() {
            return Messages.EntraCertificatePemCredentials_DisplayName();
        }

        /**
         * Validates certificate PEM input.
         */
        @SuppressWarnings("unused")
        public FormValidation doCheckCertificatePem(@QueryParameter String value) {
            try {
                PemUtils.parseCertificate(value);
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error(Messages.FormValidation_ErrorWithDetail(e.getMessage()));
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_CertificatePemInvalid());
            }
        }

        /**
         * Validates private key PEM input.
         */
        @SuppressWarnings("unused")
        public FormValidation doCheckPrivateKeyPem(
                @QueryParameter String value, @QueryParameter Secret privateKeyPassword) {
            try {
                PemUtils.parsePrivateKey(value, Secret.toString(privateKeyPassword));
                return FormValidation.ok();
            } catch (IllegalArgumentException e) {
                return FormValidation.error(Messages.FormValidation_ErrorWithDetail(e.getMessage()));
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_PrivateKeyPemInvalid());
            }
        }

        /**
         * Tests token acquisition with the provided settings.
         */
        @RequirePOST
        @SuppressWarnings("unused")
        public FormValidation doTestConnection(
                @QueryParameter String tenantId,
                @QueryParameter String clientId,
                @QueryParameter Secret certificatePem,
                @QueryParameter Secret privateKeyPem,
                @QueryParameter Secret privateKeyPassword,
                @QueryParameter String scopes,
                @QueryParameter String username,
                @QueryParameter String authorityHost) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);

            if (Util.fixEmptyAndTrim(tenantId) == null) {
                return FormValidation.error(Messages.FormValidation_TenantIdRequired());
            }
            if (Util.fixEmptyAndTrim(clientId) == null) {
                return FormValidation.error(Messages.FormValidation_ClientIdRequired());
            }
            if (ScopeUtils.parseScopes(scopes).isEmpty()) {
                return FormValidation.error(Messages.FormValidation_ScopesRequired());
            }

            try {
                EntraCertificatePemCredentials credentials = new EntraCertificatePemCredentials(
                        CredentialsScope.SYSTEM,
                        "test",
                        null,
                        tenantId,
                        clientId,
                        certificatePem,
                        privateKeyPem,
                        privateKeyPassword,
                        scopes,
                        username,
                        authorityHost);
                Secret token =
                        credentials.getAccessToken(new EntraOAuth2ScopeRequirement(ScopeUtils.parseScopes(scopes)));
                if (token == null || Util.fixEmptyAndTrim(token.getPlainText()) == null) {
                    return FormValidation.error(Messages.FormValidation_TestTokenFailed());
                }
                return FormValidation.ok(Messages.FormValidation_TestTokenSuccess());
            } catch (Exception e) {
                return FormValidation.error(Messages.FormValidation_TestTokenErrorWithDetail(e.getMessage()));
            }
        }
    }
}
