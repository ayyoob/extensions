package org.wso2.carbon.andes.extensions.authentication.mqtt.oauth;

/**
 * Interface to be implemented for custom oauth endpoint
 */
public interface TokenAuthenticator {
	/**
	 * This method gets a string accessToken and validates it
	 *
	 * @param token which need to be validated.
	 * @return boolean with the validated results.
	 */
	boolean validateToken(String token);

}
