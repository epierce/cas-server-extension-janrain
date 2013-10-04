package edu.usf.cims.cas.support.janrain.authentication.principal;

import org.jasig.cas.authentication.principal.AbstractPersonDirectoryCredentialsToPrincipalResolver;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.CredentialsToPrincipalResolver;

/**
 * This class resolves the principal (OpenID URL) from the Janrain credential (token that is passed to the auth_info webservice)
 *
 * @author Eric Pierce
 * @since 0.1
 */
public final class JanrainCredentialsToPrincipalResolver extends AbstractPersonDirectoryCredentialsToPrincipalResolver
    implements CredentialsToPrincipalResolver {

    @Override
    protected String extractPrincipalId(final Credentials credentials) {
        JanrainCredentials janrainCredentials = (JanrainCredentials) credentials;
        String principal = janrainCredentials.getIdentifier();
        return principal;
    }

    public boolean supports(final Credentials credentials) {
        return credentials != null && (JanrainCredentials.class.isAssignableFrom(credentials.getClass()));
    }
}