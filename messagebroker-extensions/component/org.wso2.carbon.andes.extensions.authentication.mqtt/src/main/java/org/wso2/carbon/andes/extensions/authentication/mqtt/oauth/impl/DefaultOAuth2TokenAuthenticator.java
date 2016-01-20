package org.wso2.carbon.andes.extensions.authentication.mqtt.oauth.impl;

import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.ssl.KeyMaterial;
import org.wso2.andes.configuration.modules.JKSStore;
import org.wso2.carbon.andes.extensions.authentication.mqtt.config
		.MqttAuthenticationConfigurationManager;
import org.wso2.carbon.andes.extensions.authentication.mqtt.oauth.TokenAuthenticator;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationResponseDTO;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

public class DefaultOAuth2TokenAuthenticator implements TokenAuthenticator {
	private static final Log log = LogFactory.getLog(DefaultOAuth2TokenAuthenticator.class);
	private static final String TOKEN_TYPE = "bearer";
	private static final int TIMEOUT_IN_MILLIS = 15 * 60 * 1000;
	private List<String> scopes;
	private OAuth2TokenValidationServiceStub tokenValidationServiceStub;
	private String cookie;

	public DefaultOAuth2TokenAuthenticator(){
		initialize();
	}

	/**
	 * This method initialize the  tokenValidationServiceStub to communicate with the OAuth2TokenValidationService
	 */
	private void initialize() {
		MqttAuthenticationConfigurationManager config =
				MqttAuthenticationConfigurationManager.getInstance();

		//Create the stub to call oauth validation endpoint
		URL hostURL = config.getHostUrl();
		if (hostURL != null) {
			try {
				ConfigurationContext configCtx =
						ConfigurationContextFactory.createConfigurationContextFromFileSystem(
								null, null);
				tokenValidationServiceStub = new OAuth2TokenValidationServiceStub(configCtx,
																				  hostURL.toString
																						  ());
				ServiceClient client = tokenValidationServiceStub._getServiceClient();
				HttpTransportProperties.Authenticator auth =
						new HttpTransportProperties.Authenticator();
				auth.setPreemptiveAuthentication(true);
				String username = config.getUsername();
				String password = config.getPassword();
				auth.setPassword(username);
				auth.setUsername(password);
				Options options = client.getOptions();
				options.setProperty(HTTPConstants.AUTHENTICATE, auth);
				options.setTimeOutInMilliSeconds(TIMEOUT_IN_MILLIS);
				options.setProperty(HTTPConstants.SO_TIMEOUT, TIMEOUT_IN_MILLIS);
				options.setProperty(HTTPConstants.CONNECTION_TIMEOUT, TIMEOUT_IN_MILLIS);
				options.setProperty(HTTPConstants.REUSE_HTTP_CLIENT, Constants.VALUE_TRUE);
				options.setCallTransportCleanup(true);
				options.setManageSession(true);

				if (hostURL.getProtocol().equals("https")) {
					try {
						EasySSLProtocolSocketFactory sslProtocolSocketFactory = createProtocolSocketFactory();
						Protocol authhttps = new Protocol("https", sslProtocolSocketFactory,
														  hostURL.getPort());
						Protocol.registerProtocol("https", authhttps);
						options.setProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER, authhttps);

					} catch (Exception e) {
						log.error("An error in initializing SSL Context", e);
					}
				}
				client.setOptions(options);
			} catch (AxisFault e) {
				log.error("Error occurred while initializing Axis2 Configuration Context. " +
								  "Please check if an appropriate axis2.xml is provided", e);
			}

			scopes = config.getScopes();
		}

	}

	/**
	 * This method gets a string accessToken and validates it
	 *
	 * @param token which need to be validated.
	 * @return boolean with the validated results.
	 */
	@Override
	public boolean validateToken(String token) {
		if (cookie != null) {
			tokenValidationServiceStub._getServiceClient().getOptions().setProperty(
					HTTPConstants.COOKIE_STRING, cookie);
		}

		OAuth2TokenValidationRequestDTO validationRequest = new OAuth2TokenValidationRequestDTO();
		OAuth2TokenValidationRequestDTO_OAuth2AccessToken accessToken =
				new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();
		accessToken.setTokenType(TOKEN_TYPE);
		accessToken.setIdentifier(token);
		validationRequest.setAccessToken(accessToken);

		OAuth2TokenValidationResponseDTO tokenValidationResponse =
				null;
		try {
			tokenValidationResponse = tokenValidationServiceStub.validate(validationRequest);
		} catch (RemoteException e) {
			log.error("Error on connecting with the validation endpoint", e);
			return false;
		}

		ServiceContext serviceContext =
				tokenValidationServiceStub._getServiceClient().getLastOperationContext()
						.getServiceContext();
		cookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING);

		/*If scopes are configured in broker.xml, then it will compare the
		scopes with the token validation response and if the required scopes are in response scope
		 then user will be authenticated*/
		boolean scopeValidation = tokenValidationResponse.getValid();
		if (scopeValidation && scopes != null) {
			String validateResponseScope[] = tokenValidationResponse.getScope();
			List<String> responseScopes = Arrays.asList(validateResponseScope);
			for (String requiredScope : scopes) {
				if (!responseScopes.contains(requiredScope)) {
					scopeValidation = false;
					break;
				}
			}
		}
		return scopeValidation;
	}

	private EasySSLProtocolSocketFactory createProtocolSocketFactory()
			throws GeneralSecurityException, IOException {
		EasySSLProtocolSocketFactory easySSLPSFactory = new EasySSLProtocolSocketFactory();

		KeyMaterial km = null;
		JKSStore jksKeyStore = MqttAuthenticationConfigurationManager.getInstance().getJksKeyStore();
		String keyStoreLocation = jksKeyStore.getStoreLocation();
		char[] password = jksKeyStore.getPassword().toCharArray();
		File f = new File(keyStoreLocation);
		if (f.exists()) {
			try {
				km = new KeyMaterial(keyStoreLocation, password);
				log.trace("Keystore location is: " + keyStoreLocation + "");
			} catch (GeneralSecurityException gse) {

				log.error("Exception occured while loading keystore from the following location: " +

								  keyStoreLocation, gse);
				throw gse;

			}
		} else {
			log.error("Unable to load Keystore from the following location: " + keyStoreLocation);
			throw new GeneralSecurityException(
					"Unable to load Keystore from the following location: " + keyStoreLocation);
		}

		easySSLPSFactory.setKeyMaterial(km);
		return easySSLPSFactory;
	}
}
