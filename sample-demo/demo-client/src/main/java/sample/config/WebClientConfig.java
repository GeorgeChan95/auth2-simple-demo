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
package sample.config;

import sample.authorization.DeviceCodeOAuth2AuthorizedClientProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 0.0.1
 */
@Configuration
public class WebClientConfig {

	/**
	 * 配置一个 WebClient,用于与外部服务交互。
	 * WebClient 是 Spring 提供的非阻塞、响应式 HTTP 客户端,
	 * 每次发送请求时，WebClient 会通过 OAuth2AuthorizedClientManager 自动处理获取或刷新 Access Token，并附加到请求头中。
	 * @param authorizedClientManager
	 * @return
	 */
	@Bean
	public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
		// 使用 ServletOAuth2AuthorizedClientExchangeFilterFunction，它会拦截 HTTP 请求并自动为其附加 OAuth2 授权头（如 Access Token）
		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		// @formatter:off
		return WebClient.builder()
				.apply(oauth2Client.oauth2Configuration())
				.build();
		// @formatter:on
	}

	/**
	 * Spring Security 提供的核心接口，管理 OAuth2 授权客户端的生命周期。
	 * 它根据不同的授权模式和客户端配置，自动处理授权、令牌刷新等逻辑。
	 * @param clientRegistrationRepository 用于存储和检索已注册的 OAuth2 客户端信息（ClientRegistration）
	 * @param authorizedClientRepository 用于存储已授权的 OAuth2 客户端及其关联的访问令牌（OAuth2AuthorizedClient）。
	 * @return
	 */
	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		// @formatter:off
		// 配置授权提供器 (OAuth2AuthorizedClientProvider)，用于组合多个授权提供器。
		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode() // 支持授权码模式
						.refreshToken() // 支持刷新令牌
						.clientCredentials() // 支持客户端凭据模式
						.provider(new DeviceCodeOAuth2AuthorizedClientProvider()) // 支持设备码模式（自定义）。
						.build();
		// @formatter:on

		// DefaultOAuth2AuthorizedClientManager 将基于这两个存储库来管理 OAuth2 客户端的授权和访问令牌。
		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		// 配置 DefaultOAuth2AuthorizedClientManager 使用的 授权提供器（OAuth2AuthorizedClientProvider），以确定如何处理授权。
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		// Set a contextAttributesMapper to obtain device_code from the request
		// 设置 ContextAttributesMapper， 用于从上下文中获取必要的属性（如设备码）
		authorizedClientManager.setContextAttributesMapper(DeviceCodeOAuth2AuthorizedClientProvider
				.deviceCodeContextAttributesMapper());

		return authorizedClientManager;
	}

}
