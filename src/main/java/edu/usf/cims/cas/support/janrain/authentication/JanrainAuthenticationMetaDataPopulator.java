package edu.usf.cims.cas.support.janrain.authentication;

import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.AuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.MutableAuthentication;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import edu.usf.cims.cas.support.janrain.authentication.principal.JanrainCredentials;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is a meta data populator for authentication using Janrain Engage.
 *
 * @author Eric Pierce
 * @since 0.1
 */
public final class JanrainAuthenticationMetaDataPopulator implements AuthenticationMetaDataPopulator {

    private static final Logger LOGGER = LoggerFactory.getLogger(JanrainAuthenticationMetaDataPopulator.class);

    public Authentication populateAttributes(Authentication authentication, Credentials credentials) {
        if (credentials instanceof JanrainCredentials) {
          JanrainCredentials janrainCredentials = (JanrainCredentials) credentials;
          final Principal simplePrincipal = new SimplePrincipal(authentication.getPrincipal().getId(), janrainCredentials.getUserAttributes());
            LOGGER.debug("Added Attributes [{}] to SimplePrincipal [{}]", janrainCredentials.getUserAttributes(), simplePrincipal);

            //Create a new Authentication object with this principal
            final MutableAuthentication mutableAuthentication = new MutableAuthentication(simplePrincipal, authentication.getAuthenticatedDate());
            mutableAuthentication.getAttributes().putAll(authentication.getAttributes());

            return mutableAuthentication;
        }
        return authentication;
    }
}