package edu.usf.cims.cas.support.janrain.authentication.principal;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

import org.springframework.util.Assert;

import org.apache.commons.lang.StringUtils;

import org.jasig.cas.authentication.principal.Credentials;
import com.googlecode.janrain4j.api.engage.response.profile.Profile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class creates a CAS-compatible credential using data from Janrain Engage
 *
 * @author Eric Pierce
 * @since 0.1
 */
public final class JanrainCredentials implements Credentials {

    private static final long serialVersionUID = 2749515040385101768L;

    private static final Logger LOGGER = LoggerFactory.getLogger(JanrainCredentials.class);

    /** The token that will sent to the Janrain user_info service */
    private String token;

    private String identifier;

    private Map<String, Object> userAttributes;

    public JanrainCredentials(final String token) {
        Assert.notNull(token, "token cannot be null");
        this.token = token;
    }

    public final void setToken(final String token) {
        this.token = token;
    }

    public final String getToken() {
        return this.token;
    }

    public final void setIdentifier(final String identifier) {
        this.identifier = identifier;
    }

    public final String getIdentifier() {
        return this.identifier;
    }

    /**
    * Create a map of the User's Attributes from a janrain4j Profile object
    *
    * @param userProfile
    * @param friendList
    */
    public void setUserAttributes(Profile userProfile, List<String> friendList) {

        Map<String,Object> userAttributes = new HashMap<String,Object>();

        if(userProfile.getProviderName() != null){
            userAttributes.put("ProviderName", userProfile.getProviderName());
            LOGGER.debug("Set ProviderName: {}", userProfile.getProviderName());
        }
        if(userProfile.getPrimaryKey() != null){
            userAttributes.put("PrimaryKey", userProfile.getPrimaryKey());
            LOGGER.debug("Set PrimaryKey: {}", userProfile.getPrimaryKey());
        }
        if(userProfile.getDisplayName() != null){
            userAttributes.put("DisplayName", userProfile.getDisplayName());
            LOGGER.debug("Set DisplayName: {}", userProfile.getDisplayName());
        }
        if(userProfile.getName() != null) {
            if(userProfile.getName().getFamilyName() != null){
                userAttributes.put("FamilyName", userProfile.getName().getFamilyName());
                LOGGER.debug("Set FamilyName: {}", userProfile.getName().getFamilyName());
            }
            if(userProfile.getName().getGivenName() != null){
                userAttributes.put("GivenName", userProfile.getName().getGivenName());
                LOGGER.debug("Set GivenName: {}", userProfile.getName().getGivenName());
            }
        }
        if(userProfile.getBirthday() != null){
            userAttributes.put("Birthday", userProfile.getBirthday());
            LOGGER.debug("Set Birthday: {}", userProfile.getBirthday());
        }
        /*
         * If the 'VerifiedEmail' attribute exists, use that as the user's email address.
         * If not, look for 'Email'
         */
        if(userProfile.getVerifiedEmail() != null){
            userAttributes.put("Email", userProfile.getVerifiedEmail());
            LOGGER.debug("Set Email: {}", userProfile.getVerifiedEmail());
        } else if(userProfile.getEmail() != null){
            userAttributes.put("Email", userProfile.getEmail());
            LOGGER.debug("Set Email: {}", userProfile.getEmail());
        }
        if(userProfile.getProviderName() != null){
            userAttributes.put("PhoneNumber", userProfile.getPhoneNumber());
            LOGGER.debug("Set PhoneNumber: {}", userProfile.getPhoneNumber());
        }
        if(userProfile.getPreferredUsername() != null){
            userAttributes.put("PreferredUsername", userProfile.getPreferredUsername());
            LOGGER.debug("Set PreferredUsername: {}", userProfile.getPreferredUsername());
        }
        if(userProfile.getPhoto() != null){
            userAttributes.put("PhotoURL", userProfile.getPhoto());
            LOGGER.debug("Set PhotoURL: {}", userProfile.getPhoto());
        }
        if(userProfile.getUrl() != null){
            userAttributes.put("Url", userProfile.getUrl());
            LOGGER.debug("Set Url: {}", userProfile.getUrl());
        }
        if(userProfile.getUtcOffset() != null){
            userAttributes.put("UTCoffset", userProfile.getUtcOffset());
            LOGGER.debug("Set UTCoffset: {}", userProfile.getUtcOffset());
        }
        if(userProfile.getGender() != null){
            userAttributes.put("Gender", userProfile.getGender());
            LOGGER.debug("Set Gender: {}", userProfile.getGender());
        }
        if(userProfile.getAddress() != null) {
            if(userProfile.getAddress().getCountry() != null){
                userAttributes.put("Country", userProfile.getAddress().getCountry());
                LOGGER.debug("Set Country: {}", userProfile.getAddress().getCountry());
            }
            if(userProfile.getAddress().getLocality() != null){
                userAttributes.put("Locality", userProfile.getAddress().getLocality());
                LOGGER.debug("Set Locality: {}", userProfile.getAddress().getLocality());
            }
            if(userProfile.getAddress().getPostalCode() != null){
                userAttributes.put("PostalCode", userProfile.getAddress().getPostalCode());
                LOGGER.debug("Set PostalCode: {}", userProfile.getAddress().getPostalCode());
            }
            if(userProfile.getAddress().getStreetAddress() != null){
                userAttributes.put("StreetAddress", userProfile.getAddress().getStreetAddress());
                LOGGER.debug("Set StreetAddress: {}", userProfile.getAddress().getStreetAddress());
            }
        }
        if(friendList.size() > 0){
            userAttributes.put("FriendList", friendList);
            LOGGER.debug("Set FriendList: {}", friendList);
        }
        this.userAttributes = userAttributes;
    }

    /**
    * Alternate method used when the friend list is not available.
    *
    * @param userProfile
    *
    */
    public void setUserAttributes(Profile userProfile) {
        setUserAttributes(userProfile, new ArrayList<String>());
    }


    public final Map<String, Object> getUserAttributes() {
        return this.userAttributes;
    }

    public String toString() {
        if (StringUtils.isNotBlank(this.identifier)){
            return this.identifier;
        } else {
            return "[janrain token: " + this.token + "]";
        }
    }
}