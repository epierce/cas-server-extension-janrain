package edu.usf.cims.cas.support.janrain.authentication.handler.support;

import com.googlecode.janrain4j.api.engage.EngageFailureException;
import com.googlecode.janrain4j.api.engage.ErrorResponeException;
import com.googlecode.janrain4j.api.engage.EngageService;
import com.googlecode.janrain4j.api.engage.EngageServiceFactory;
import com.googlecode.janrain4j.api.engage.response.UserDataResponse;

import org.jasig.cas.authentication.handler.AuthenticationException;
import org.jasig.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.jasig.cas.authentication.principal.Credentials;
import edu.usf.cims.cas.support.janrain.authentication.principal.JanrainCredentials;
import org.springframework.webflow.context.ExternalContextHolder;

/**
 * This handler authenticates Janrain credentials : it submits the token to the Janrain auth_info webservice
 * using the janrain4j library.
 *
 * @author Eric Pierce
 * @since 0.1
 */
public final class JanrainAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler {

    private EngageService engageService = EngageServiceFactory.getEngageService();

    public boolean supports(Credentials credentials) {
        return credentials != null && (JanrainCredentials.class.isAssignableFrom(credentials.getClass()));
    }

    @Override
    protected boolean doAuthentication(Credentials credentials) throws AuthenticationException {
        JanrainCredentials credential = (JanrainCredentials) credentials;
        log.debug("Got Credential : {}", credential);

        try {
            UserDataResponse userDataResponse = engageService.authInfo(credential.getToken(), true);

            if (userDataResponse.getProfile() != null ) {
                log.debug("userDataResponse : {}", userDataResponse.getResponseAsJSON());
                credential.setIdentifier(userDataResponse.getProfile().getIdentifier());
                if(userDataResponse.getProfile() != null) {
                    if(userDataResponse.getFriends() != null) {
                        credential.setUserAttributes(userDataResponse.getProfile(), userDataResponse.getFriends());
                    } else {
                        credential.setUserAttributes(userDataResponse.getProfile());
                    }
                }
                return true;
            } else {
                return false;
            }
        }
        catch (EngageFailureException e) {
                log.warn(e.getMessage());
                return false;
        }
        catch (ErrorResponeException e) {
                log.warn(e.getMessage());
                return false;
        }
    }

}