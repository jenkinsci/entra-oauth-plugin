# Entra OAuth Credentials Plugin

This plugin provides OAuth 2.0 credentials backed by Microsoft Entra (Azure AD) service principals. It implements the `oauth-credentials` interfaces so other Jenkins plugins (like email-ext) can request OAuth tokens.

## Credentials Provided

Credentials provided (client credentials flow, non-interactive):
- `Entra service principal (client secret)`
- `Entra service principal (PFX certificate)`
- `Entra service principal (PEM certificate)`

## Create a Credential

1. Go to **Manage Jenkins** ? **Credentials**.
2. Add a credential of type **Entra service principal (client secret)** or **Entra service principal (certificate)**.
3. Fill in:
   - `Tenant ID`: e.g., tenant GUID or `organizations` / `common` / `consumers`.
   - `Client ID`: application (client) ID.
   - `Client Secret` or certificate fields depending on the type.
   - `Scopes`: one per line or comma-separated.
   - `Authority Host` (optional): defaults to `https://login.microsoftonline.com`.

## Configuration as Code (JCasC)

Client secret:

```yaml
credentials:
  system:
    domainCredentials:
      - credentials:
          - entraClientSecret:
              scope: GLOBAL
              id: "Entra-client-secret"
              description: "Entra client secret"
              tenantId: "organizations"
              clientId: "client-id"
              clientSecret: "secret-value"
              scopes: "scope1, scope2"
              username: "user@example.com"
              authorityHost: "https://login.microsoftonline.com"
```

PFX certificate:

```yaml
credentials:
  system:
    domainCredentials:
      - credentials:
          - entraCertPfx:
              scope: GLOBAL
              id: "Entra-cert-pfx"
              description: "Entra cert PFX"
              tenantId: "tenant-guid"
              clientId: "client-id"
              certificateBase64: "dGVzdA=="
              certificatePassword: "pfx-password"
              scopes: "scope1"
              username: "user@example.com"
              authorityHost: "https://login.microsoftonline.com"
```

PEM certificate:

```yaml
credentials:
  system:
    domainCredentials:
      - credentials:
          - entraCertPem:
              scope: GLOBAL
              id: "Entra-cert-pem"
              description: "Entra cert PEM"
              tenantId: "tenant-guid"
              clientId: "client-id"
              certificatePem: |
                -----BEGIN CERTIFICATE-----
                ...
                -----END CERTIFICATE-----
              privateKeyPem: |
                -----BEGIN PRIVATE KEY-----
                ...
                -----END PRIVATE KEY-----
              scopes: "scope1"
              username: "user@example.com"
              authorityHost: "https://login.microsoftonline.com"
```

Multiple credentials + domain requirements example:

```yaml
credentials:
  system:
    domainCredentials:
      - domain:
          name: "Office 365"
          specifications:
            - entraOAuth2ScopeSpecification:
                specifiedScopesText: |
                  https://outlook.office365.com/.default
        credentials:
          - entraClientSecret:
              scope: GLOBAL
              id: "o365-client-secret"
              description: "O365 client secret"
              tenantId: "organizations"
              clientId: "client-id"
              clientSecret: "secret-value"
              scopes: "https://outlook.office365.com/.default"
              username: "user@example.com"
              authorityHost: "https://login.microsoftonline.com"
      - credentials:
          - entraCertPfx:
              scope: GLOBAL
              id: "graph-cert-pfx"
              description: "Graph cert PFX"
              tenantId: "tenant-guid"
              clientId: "client-id"
              certificateBase64: "dGVzdA=="
              certificatePassword: "pfx-password"
              scopes: "https://graph.microsoft.com/.default"
              username: "user@example.com"
              authorityHost: "https://login.microsoftonline.com"
```

## Scopes

Scopes are passed directly to MSAL4J and are not modified by the plugin. For client credentials, Entra commonly expects a `/.default` scope, for example:

```
https://outlook.office365.com/.default
```

The plugin allows any scope list; validation only checks that at least one scope is provided.

## Domain Requirements (Scopes)

The plugin adds a domain specification:
- **Entra OAuth 2.0 scope specification**

This can be used in Jenkins credential domains to filter which credentials match required scopes.

## Notes

- Tokens are cached in memory via MSAL4J's confidential client instance.
- PEM private keys must be PKCS#8 (`BEGIN PRIVATE KEY`).




