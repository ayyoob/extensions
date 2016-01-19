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

package org.wso2.carbon.andes.extensions.authentication.mqtt.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.andes.configuration.AndesConfigurationManager;
import org.wso2.andes.configuration.enums.AndesConfiguration;
import org.wso2.andes.kernel.AndesException;
import org.wso2.carbon.andes.extensions.authentication.mqtt.config
		.MqttAuthenticationConfigurationManager;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.base.api.ServerConfigurationService;

/**
 * @scr.component name="org.wso2.carbon.andes.extensions.authentication.mqtt.internal
 * .MqttAuthenticatorServiceComponent" immediate="true"
 * @scr.reference name="server.configuration"
 * interface="org.wso2.carbon.base.api.ServerConfigurationService"
 * cardinality="1..1"
 * policy="dynamic"
 * bind="setServerConfiguration"
 * unbind="unsetServerConfiguration"
 */

//* @scr.reference name="TenantMgtListener"
//		* interface="org.wso2.carbon.stratos.common.listeners.TenantMgtListener"
//		* cardinality="1..n"
//		* policy="dynamic"
//		* bind="setTenantMgtListenerService"
//		* unbind="unsetTenantMgtListenerService"
public class MqttAuthenticatorServiceComponent {

	private static final Log log = LogFactory.getLog(MqttAuthenticatorServiceComponent.class);
	private static final String CARBON_CONFIG_PORT_OFFSET = "Ports.Offset";
	private static final int CARBON_DEFAULT_PORT_OFFSET = 0;

	protected void activate(ComponentContext componentContext) throws AndesException {

		//reinitializing Andes Configuration manager, since we cannot guarantee the startup order of
		AndesConfigurationManager.initialize(getPortOffset());
		MqttAuthenticationConfigurationManager.getInstance().initConfig();
		log.info("Initiating Mqtt Authenticator");
	}

	protected void deactivate(ComponentContext componentContext) {
		if (log.isDebugEnabled()) {
			log.debug("Authenticator bundle is deactivated");
		}
	}

	private int getPortOffset() {
		ServerConfiguration carbonConfig = ServerConfiguration.getInstance();
		String portOffset = System.getProperty("portOffset",
											   carbonConfig.getFirstProperty(CARBON_CONFIG_PORT_OFFSET));
		try {
			return ((portOffset != null) ? Integer.parseInt(portOffset.trim()) : CARBON_DEFAULT_PORT_OFFSET);
		} catch (NumberFormatException e) {
			return CARBON_DEFAULT_PORT_OFFSET;
		}
	}

	//wait till serverConfigurationService is started to pick the carbon offset
	protected void setServerConfiguration(ServerConfigurationService serverConfiguration) {

	}

	protected void unsetServerConfiguration(ServerConfigurationService serverConfiguration) {
	}

//	/*
//		wait till specific TenantMgtListener registered with the andes
//		https://github.com/wso2/carbon-business-messaging/blob/v3.0.1/components/andes/org.wso2.carbon.andes/src/main/java/org/wso2/carbon/andes/internal/QpidServiceComponent.java#L143
//	*/
//	protected void setTenantMgtListenerService(TenantMgtListener service) {
//		String serviceClassName = service.getClass().getName();
//
//		//initialize only after below service is registered. This implementation needs to be changed
//		String requiredServiceClassName =
//				"org.wso2.carbon.andes.listeners.MessageBrokerTenantManagementListener";
//		if (requiredServiceClassName.equals(serviceClassName)) {
//			log.info("Initiating Mqtt Authenticator");
//			MqttAuthenticationConfigurationManager.getInstance().initConfig();
//		}
//
//
//	}
//
//	protected void unsetTenantMgtListenerService(TenantMgtListener service) {
//	}
}
