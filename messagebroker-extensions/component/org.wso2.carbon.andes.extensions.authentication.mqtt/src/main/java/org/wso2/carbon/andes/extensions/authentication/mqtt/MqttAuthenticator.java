/*
*  Copyright (c) 2016 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing,
*  software distributed under the License is distributed on an
*  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*  KIND, either express or implied.  See the License for the
*  specific language governing permissions and limitations
*  under the License.
*/
package org.wso2.carbon.andes.extensions.authentication.mqtt;

import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;
import org.apache.commons.httpclient.contrib.ssl.TrustSSLProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dna.mqtt.moquette.server.IAuthenticator;
import org.wso2.andes.configuration.modules.JKSStore;
import org.wso2.carbon.andes.extensions.authentication.mqtt.config
		.MqttAuthenticationConfigurationManager;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationResponseDTO;

import java.io.File;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.List;

/**
 * This implementation supports both basic authentication and oauth
 * if username and password is sent through the mqtt connection then it will be considered as
 * basic authentication
 * and if the password is empty then it will consider is a token based authentication.
 */
public class MqttAuthenticator implements IAuthenticator {


	private static final Log log = LogFactory.getLog(MqttAuthenticator.class);
	private static final String TOKEN_TYPE = "bearer";
	private String basicAuthenticatorClassName;

	private IAuthenticator basicAuthenticator;
	private List<String> scopes;
	private OAuth2TokenValidationServiceStub tokenValidationServiceStub;
	private static final int TIMEOUT_IN_MILLIS = 15 * 60 * 1000;
	private String cookie;
	private boolean isInitialized;

	public MqttAuthenticator() {
		initializeAuthenticator();
	}

	/**
	 * initialize the authenticator with all the values that will be used to connect to identity
	 * server
	 */
	private void initializeAuthenticator() {
		//read the configuration file
		MqttAuthenticationConfigurationManager config =
				MqttAuthenticationConfigurationManager.getInstance();

		//read the class name of the authenticator that has to be executed when the password exist
		basicAuthenticatorClassName = config.getBasicAuthenticatorClassName();
		try {
			Class<? extends IAuthenticator> authenticatorClass = Class.forName(
					basicAuthenticatorClassName).asSubclass(IAuthenticator.class);
			basicAuthenticator = authenticatorClass.newInstance();
		} catch (Exception e) {
			log.error("failed to create an instance of the basicAuthenticator class " +
							  basicAuthenticatorClassName);
		}

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
						// Get SSL context
						JKSStore keyStore = config.getJksKeyStore();
						String keystoreLocation = keyStore.getStoreLocation();
						String keyStorePassword = keyStore.getPassword();
						Protocol authhttps = new Protocol("https", new TrustSSLProtocolSocketFactory(
														keystoreLocation, keyStorePassword.toCharArray()),
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
		isInitialized = true;

	}

	@Override
	public boolean checkValid(String token, String password) {
		//To Cater Basic and Oauth Authentication, if Password is not empty and if the basic
		// authenticator is mentioned then it will execute the basic authenticator
		if ((!password.isEmpty()) && (!basicAuthenticatorClassName.isEmpty())) {
			if (basicAuthenticator != null) {
				return basicAuthenticator.checkValid(token, password);
			}
		}

		boolean isAuthenticated = false;
		if (tokenValidationServiceStub != null) {
			try {
				isAuthenticated = validateToken(token);
			} catch (RemoteException e) {
				log.error("Error on validation with the external endpoint", e);
			}
		}
		return isAuthenticated;
	}

	/**
	 * This method gets a string accessToken and validates it
	 *
	 * @param token which need to be validated.
	 * @return boolean with the validated results.
	 */
	private boolean validateToken(String token) throws RemoteException {
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
				tokenValidationServiceStub.validate(validationRequest);

		ServiceContext serviceContext =
				tokenValidationServiceStub._getServiceClient().getLastOperationContext()
						.getServiceContext();
		cookie = (String) serviceContext.getProperty(HTTPConstants.COOKIE_STRING);

		/*If scopes are configured in broker.xml, then it will compare the
		scopes with the token validation response and if the required scopes are in response scope
		 then user will
		be authenticated*/
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
}
