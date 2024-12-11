/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.authorization;

import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 *  OAuth2 设备授权码模式中的授权请求
 *  封装 OAuth2 设备授权码模式（Device Code Grant）的授权请求相关信息,用于表示客户端发送给授权服务器的请求。
 * @author Steve Riesenberg
 * @since 1.1
 */
public final class OAuth2DeviceGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

	// 储设备授权码模式中用户设备的授权码（device_code）
	private final String deviceCode;

	/**
	 * 指定授权类型为 DEVICE_CODE,保存客户端注册信息。
	 * @param clientRegistration 客户端注册信息，封装了 OAuth2 客户端的相关配置（如 clientId、clientSecret 等）。
	 * @param deviceCode
	 */
	public OAuth2DeviceGrantRequest(ClientRegistration clientRegistration, String deviceCode) {
		super(AuthorizationGrantType.DEVICE_CODE, clientRegistration);
		Assert.hasText(deviceCode, "deviceCode cannot be empty");
		this.deviceCode = deviceCode;
	}

	/**
	 * 返回当前实例中存储的 deviceCode。
	 * 在后续处理流程中，应用可以通过此方法获取设备授权码以进一步与授权服务器交互。
	 * @return
	 */
	public String getDeviceCode() {
		return this.deviceCode;
	}

}
