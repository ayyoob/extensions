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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dna.mqtt.moquette.server.IAuthenticator;
import org.wso2.carbon.andes.extensions.authentication.mqtt.config
		.MqttAuthenticationConfigurationManager;
import org.wso2.carbon.andes.extensions.authentication.mqtt.oauth.TokenAuthenticator;

/**
 * This implementation supports both basic authentication and oauth
 * if username and password is sent through the mqtt connection then it will be considered as
 * basic authentication
 * and if the password is empty then it will consider is a token based authentication.
 */
public class MqttAuthenticator implements IAuthenticator {


	private static final Log log = LogFactory.getLog(MqttAuthenticator.class);
	private String basicAuthenticatorClassName;
	private IAuthenticator basicAuthenticator;
	private String tokenAuthenticatorClassName;
	private TokenAuthenticator tokenAuthenticator;

	public MqttAuthenticator() {
		initializeAuthenticator();
	}

	/**
	 * initialize the authenticator with all the values that will be used to connect to either either basic or token endpoint
	 */
	private void initializeAuthenticator() {
		//read the configuration file
		MqttAuthenticationConfigurationManager config =
				MqttAuthenticationConfigurationManager.getInstance();

		//read the class name of the authenticator that has to be executed when the password exist
		basicAuthenticatorClassName = config.getBasicAuthenticatorClassName();
		try {
			Class<? extends IAuthenticator> basicAuthenticatorClass = Class.forName(
					basicAuthenticatorClassName).asSubclass(IAuthenticator.class);
			basicAuthenticator = basicAuthenticatorClass.newInstance();
		} catch (Exception e) {
			log.error("failed to create an instance of the basicAuthenticator class " +
							  basicAuthenticatorClassName);
		}

		tokenAuthenticatorClassName = config.getTokenAuthenticatorClassName();
		try {
			Class<? extends TokenAuthenticator> tokenAuthenticatorClass = Class.forName(
					tokenAuthenticatorClassName).asSubclass(TokenAuthenticator.class);
			tokenAuthenticator = tokenAuthenticatorClass.newInstance();
		} catch (Exception e) {
			log.error("failed to create an instance of the tokeAuthenticator class " +
							  tokenAuthenticatorClassName);
		}


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
		return tokenAuthenticator.validateToken(token);

	}
}
