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

import java.util.Arrays;

import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * 用于处理 设备授权码模式 (Device Code Grant) 的 Access Token 请求。
 * 它主要负责发送 HTTP 请求到授权服务器的 token 端点，并解析服务器的响应，返回 OAuth2AccessTokenResponse。
 *
 * - OAuth2AccessTokenResponseClient
 *  - Spring Security OAuth2 的一个接口，负责将特定授权类型的请求转换为 Access Token 响应。
 *  - 泛型 OAuth2DeviceGrantRequest 表示处理设备授权码模式的请求。
 * @author Steve Riesenberg
 * @since 1.1
 */
public final class OAuth2DeviceAccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> {

	// 用于发送 HTTP 请求的工具，默认为 Spring 的 RestTemplate 实现,负责与授权服务器的 token 端点交互。
	private RestOperations restOperations;

	/**
	 * 创建默认的 RestTemplate 实例，并配置
	 * - 消息转换器
	 * 		- FormHttpMessageConverter：用于将表单数据序列化为 HTTP 请求体。
	 * 		- OAuth2AccessTokenResponseHttpMessageConverter：解析授权服务器返回的 Access Token 响应。
	 * - 错误处理
	 * 		- 设置 OAuth2ErrorResponseErrorHandler 来处理授权服务器返回的错误响应。
	 */
	public OAuth2DeviceAccessTokenResponseClient() {
		RestTemplate restTemplate = new RestTemplate(Arrays.asList(new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
		restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
		// 将 restTemplate 赋值给 restOperations
		this.restOperations = restTemplate;
	}

	/**
	 * 提供一个方法，允许用户自定义 RestOperations 的实现。
	 * 如果用户需要特殊的 HTTP 客户端逻辑，可以替换默认的 RestTemplate。
	 * @param restOperations
	 */
	public void setRestOperations(RestOperations restOperations) {
		this.restOperations = restOperations;
	}

	/**
	 * 发送 HTTP 请求到授权服务器的 token 端点，并解析 Access Token 响应。
	 *
	 * @param deviceGrantRequest 表示设备授权码模式的授权请求，包含 device_code 和 ClientRegistration。
	 * @return
	 */
	@Override
	public OAuth2AccessTokenResponse getTokenResponse(OAuth2DeviceGrantRequest deviceGrantRequest) {
		ClientRegistration clientRegistration = deviceGrantRequest.getClientRegistration();

		HttpHeaders headers = new HttpHeaders();
		/*
		 * 通过检查 clientAuthenticationMethod，支持公开客户端（NONE）和机密客户端（CLIENT_SECRET_BASIC）的认证。
		 *
		 * This sample demonstrates the use of a public client that does not
		 * store credentials or authenticate with the authorization server.
		 *
		 * See DeviceClientAuthenticationProvider in the authorization server
		 * sample for an example customization that allows public clients.
		 *
		 * For a confidential client, change the client-authentication-method
		 * to client_secret_basic and set the client-secret to send the
		 * OAuth 2.0 Token Request with a clientId/clientSecret.
		 */
		if (!clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) { // 如果需要进行身份校验，则需要设置请求头， 设备码模式不需要
			// 设置请求头，Authorization Basic xxx
			headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		}

		MultiValueMap<String, Object> requestParameters = new LinkedMultiValueMap<>();
		// 授权类型（urn:ietf:params:oauth:grant-type:device_code）
		requestParameters.add(OAuth2ParameterNames.GRANT_TYPE, deviceGrantRequest.getGrantType().getValue());
		// 客户端 ID
		requestParameters.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		// 设备授权码
		requestParameters.add(OAuth2ParameterNames.DEVICE_CODE, deviceGrantRequest.getDeviceCode());

		// @formatter:off
		// 构造一个 HTTP POST 请求，目标是授权服务器的 token 端点
		RequestEntity<MultiValueMap<String, Object>> requestEntity =
				RequestEntity.post(deviceGrantRequest.getClientRegistration().getProviderDetails().getTokenUri())
						.headers(headers)
						.body(requestParameters);
		// @formatter:on

		try {
			// 调用 RestOperations.exchange 方法发送请求。响应会被解析为 OAuth2AccessTokenResponse 对象。
			return this.restOperations.exchange(requestEntity, OAuth2AccessTokenResponse.class).getBody();
		} catch (RestClientException ex) {
			OAuth2Error oauth2Error = new OAuth2Error("invalid_token_response",
					"An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
							+ ex.getMessage(), null);
			throw new OAuth2AuthorizationException(oauth2Error, ex);
		}
	}

}
