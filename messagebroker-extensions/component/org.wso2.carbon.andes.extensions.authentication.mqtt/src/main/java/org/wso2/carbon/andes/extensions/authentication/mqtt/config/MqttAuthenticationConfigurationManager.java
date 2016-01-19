/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.andes.extensions.authentication.mqtt.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.andes.configuration.AndesConfigurationManager;
import org.wso2.andes.configuration.enums.AndesConfiguration;
import org.wso2.andes.configuration.modules.JKSStore;
import org.wso2.andes.configuration.util.ImmutableMetaProperties;
import org.wso2.andes.configuration.util.MetaProperties;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;


/**
 * This class acts as am access point for all config parameters used within the mqtt authenticator.
 * this configuration is read from broker.xml
 * configuration:
 *
 * <authenticatorConfig>
 *	<Parameter name="hostURL">https://localhost:9443</Parameter>
 *	<Parameter name="username">admin</Parameter>
 *	<Parameter name="password">admin</Parameter>
 *	<Parameter name="scopes"></Parameter>
 *	<Parameter name="basicAuthenticator">org.wso2.carbon.andes.authentication.andes.CarbonBasedMQTTAuthenticator</Parameter>
 </authenticatorConfig>
 */
public class MqttAuthenticationConfigurationManager {
	private static final Log log = LogFactory.getLog(MqttAuthenticationConfigurationManager.class);
	private static final String KEY_CONFIG = "transports/mqtt/security/authenticatorConfig/property[@name";

	/**
	 * The key store used for Identity Server Host.
	 */
	private static final String HOST_CONFIG[] = {"authenticatorConfigHost", KEY_CONFIG + " = 'hostURL']", "https://localhost:9443"};

	/**
	 * The key store used for username to be used for Identity Server.
	 */
	private static final String USERNAME_CONFIG[] = {"authenticatorConfigUsername", KEY_CONFIG + " = 'username']", "admin"};

	/**
	 * The key store used for password to be used for Identity Server.
	 */
	private static final String PASSWORD_CONFIG[] = {"authenticatorConfigPassword", KEY_CONFIG + " = 'password']", "password"};

	/**
	 * The key store used for password to be used for Identity Server.
	 */
	private static final String CLASS_CONFIG[] = {"authenticatorConfigDefaultAuthenticator", KEY_CONFIG + " = 'basicAuthenticator']", ""};

	/**
	 * The key store used for scopes to be used forIdentity Server .
	 */
	private static final String SCOPES_CONFIG[] = {"authenticatorConfigScopes", KEY_CONFIG + " = 'scopes']", ""};


	private URL hostUrl;
	private String username;
	private String password;
	private String basicAuthenticatorClassName;
	private JKSStore jksKeyStore;
	private JKSStore jksTrustStore;
	private List<String> scopes;

	private static final MqttAuthenticationConfigurationManager
			mqttAuthenticationConfigurationManager = new MqttAuthenticationConfigurationManager();

	public static MqttAuthenticationConfigurationManager getInstance() {
		return mqttAuthenticationConfigurationManager;
	}

	private MqttAuthenticationConfigurationManager(){
	}

	public synchronized void initConfig() {
		jksKeyStore = AndesConfigurationManager.readValue(
				AndesConfiguration.TRANSPORTS_MQTT_SSL_CONNECTION_KEYSTORE);
		jksTrustStore = AndesConfigurationManager.readValue(
				AndesConfiguration.TRANSPORTS_MQTT_SSL_CONNECTION_TRUSTSTORE);

		String hostUrlString = getConfigValue(HOST_CONFIG);
		try {
			hostUrl = new URL(hostUrlString);
		} catch (MalformedURLException e) {
			log.error("invalid token endpoint URL " + hostUrlString);
		}
		username = getConfigValue(USERNAME_CONFIG);
		password = getConfigValue(PASSWORD_CONFIG);
		basicAuthenticatorClassName = getConfigValue(CLASS_CONFIG);
		String scopeString = getConfigValue(SCOPES_CONFIG);
		if(!scopeString.isEmpty()){
			scopes = Arrays.asList(scopeString.split(" "));
		}

	}

	private MetaProperties getMetaProperties(String config[], Class<?> dataType){
		return new ImmutableMetaProperties(config[0], config[1], config[2], dataType);
	}

	private String getConfigValue(String config[]){
		MetaProperties metaProperties = getMetaProperties(config, String.class);
		String configValue = AndesConfigurationManager.readValue(new MqttAuthenticationConfiguration(metaProperties));
		return configValue.trim();
	}

	/**
	 *
	 * @return Identity Server URL
	 */
	public URL getHostUrl() {
		return hostUrl;
	}

	/**
	 *
	 * @return username to connect with Identity Server
	 */
	public String getUsername() {
		return username;
	}

	/**
	 *
	 * @return passowrd to connect with Identity Server
	 */
	public String getPassword() {
		return password;
	}

	/**
	 *
	 * @return name of the authenticator to be executed if the password fields is exist in oauth authentcator
	 */
	public String getBasicAuthenticatorClassName() {
		return basicAuthenticatorClassName;
	}

	public JKSStore getJksKeyStore() {
		return jksKeyStore;
	}

	public JKSStore getJksTrustStore() {
		return jksTrustStore;
	}

	public List<String> getScopes() {
		return scopes;
	}
}
