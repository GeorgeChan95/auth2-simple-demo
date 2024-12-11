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

import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

/**
 * DeviceCodeOAuth2AuthorizedClientProvider 是 Spring Security OAuth2 中的一个实现类，
 * 用于支持设备授权码 (Device Code Grant) 模式的客户端授权流程。它实现了 OAuth2AuthorizedClientProvider 接口，
 * 负责从设备授权码 (Device Code) 获取 Access Token，并将其包装成 OAuth2AuthorizedClient。
 *
 * @author Steve Riesenberg
 * @since 1.1
 */
public final class DeviceCodeOAuth2AuthorizedClientProvider implements OAuth2AuthorizedClientProvider {

	// 用于发送设备授权码模式的 Token 请求，默认实现是 OAuth2DeviceAccessTokenResponseClient。
    private OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> accessTokenResponseClient =
            new OAuth2DeviceAccessTokenResponseClient();

	// 时钟偏差，用于验证 Token 是否过期，允许一定的时间误差。
    private Duration clockSkew = Duration.ofSeconds(60);

	// 系统时钟，用于获取当前时间。
    private Clock clock = Clock.systemUTC();

    public void setAccessTokenResponseClient(OAuth2AccessTokenResponseClient<OAuth2DeviceGrantRequest> accessTokenResponseClient) {
        this.accessTokenResponseClient = accessTokenResponseClient;
    }

    public void setClockSkew(Duration clockSkew) {
        this.clockSkew = clockSkew;
    }

    public void setClock(Clock clock) {
        this.clock = clock;
    }

    @Override
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
        Assert.notNull(context, "context cannot be null");
        ClientRegistration clientRegistration = context.getClientRegistration();
		// 如果授权类型不是设备授权码，则直接返回 null
        if (!AuthorizationGrantType.DEVICE_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
            return null;
        }
        OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();

		// 检查是否已经授权，如果已有 Token 且未过期，则无需重新授权。
        if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {
            // If client is already authorized but access token is NOT expired than no
            // need for re-authorization
            return null;
        }
		// 如果已授权但 Access Token 过期，且有 Refresh Token，则无需处理，交由 Refresh Token 流程。
        if (authorizedClient != null && authorizedClient.getRefreshToken() != null) {
            // If client is already authorized but access token is expired and a
            // refresh token is available, delegate to refresh_token.
            return null;
        }
        // *****************************************************************
        // Get device_code set via DefaultOAuth2AuthorizedClientManager#setContextAttributesMapper()
        // *****************************************************************
		// 获取设备授权码 (device_code)
        String deviceCode = context.getAttribute(OAuth2ParameterNames.DEVICE_CODE);
        // Attempt to authorize the client, which will repeatedly fail until the user grants authorization
		// 构建设备授权码请求并获取 Token, 构建 OAuth2DeviceGrantRequest 对象，调用 getTokenResponse 获取 Access Token。
        OAuth2DeviceGrantRequest deviceGrantRequest = new OAuth2DeviceGrantRequest(clientRegistration, deviceCode);
        OAuth2AccessTokenResponse tokenResponse = getTokenResponse(clientRegistration, deviceGrantRequest);

		// 构建并返回 OAuth2AuthorizedClient
        return new OAuth2AuthorizedClient(clientRegistration, context.getPrincipal().getName(),
                tokenResponse.getAccessToken(), tokenResponse.getRefreshToken());
    }

    /**
     * 获取token请求
     * @param clientRegistration 使用 OAuth2DeviceAccessTokenResponseClient 实现
     * @param deviceGrantRequest 设备授权请求
     * @return
     */
    private OAuth2AccessTokenResponse getTokenResponse(ClientRegistration clientRegistration,
                                                       OAuth2DeviceGrantRequest deviceGrantRequest) {
        try {
            // 使用 OAuth2DeviceAccessTokenResponseClient 实现，通过 deviceGrantRequest 向授权服务器发送请求，成功返回access_token
            return this.accessTokenResponseClient.getTokenResponse(deviceGrantRequest);
        } catch (OAuth2AuthorizationException ex) {
            // 如果授权服务器返回错误，转换为 ClientAuthorizationException 抛出。
            throw new ClientAuthorizationException(ex.getError(), clientRegistration.getRegistrationId(), ex);
        }
    }

    /**
     * 判断 Token 是否过期
     * @param token
     * @return
     */
    private boolean hasTokenExpired(OAuth2Token token) {
        // 如果当前时间（clock.instant()）大于 Token 的过期时间减去时钟偏差（clockSkew），则认为 Token 已过期。
        return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

    /**
     * 设备授权码上下文属性映射
     * 提供 DefaultOAuth2AuthorizedClientManager 中上下文属性的映射方法，用于从 HTTP 请求中提取 device_code。
     * @return
     */
    public static Function<OAuth2AuthorizeRequest, Map<String, Object>> deviceCodeContextAttributesMapper() {
        return (authorizeRequest) -> {
            HttpServletRequest request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
            Assert.notNull(request, "request cannot be null");

            // 从请求中获取 device_code
            String deviceCode = request.getParameter(OAuth2ParameterNames.DEVICE_CODE);
            return (deviceCode != null) ? Collections.singletonMap(OAuth2ParameterNames.DEVICE_CODE, deviceCode) :
                    Collections.emptyMap();
        };
    }

}
