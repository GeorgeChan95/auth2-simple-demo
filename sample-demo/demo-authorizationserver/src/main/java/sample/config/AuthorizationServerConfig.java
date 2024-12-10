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

import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import sample.authentication.DeviceClientAuthenticationProvider;
import sample.federation.FederatedIdentityIdTokenCustomizer;
import sample.jose.Jwks;
import sample.web.authentication.DeviceClientAuthenticationConverter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * 一个Spring Security配置类，用于 配置OAuth2授权服务器的安全设置
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Steve Riesenberg
 * @since 1.1
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {


    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";//这个是授权页

    /**
     * 这段代码是 Spring Authorization Server 的核心安全配置，
     * 用于实现 OAuth2 授权服务器的功能，包括设备授权流（Device Authorization Grant）、客户端认证、授权端点配置，以及其他相关安全特性。
     * 官方网站的说明更具体 https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html
     *
     * @param http
     * @param registeredClientRepository
     * @param authorizationServerSettings
     * @return
     * @throws Exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // 指定此过滤器链的优先级为最高，确保它先于其他安全过滤器链执行。
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http, // Spring Security 提供的配置工具
            RegisteredClientRepository registeredClientRepository, // 用于管理 OAuth2 客户端（Registered Client）信息的存储库。
            AuthorizationServerSettings authorizationServerSettings // 授权服务器的配置类，包含端点 URL 等设置。
    ) throws Exception {
        /**
         * 应用默认安全配置
         * Spring Authorization Server 提供的默认安全配置方法，自动配置大多数授权服务器所需的安全规则（如授权端点、令牌端点等）。
         * 这是授权服务器的基础配置，代码后续会对其进行自定义扩展。
         * */
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        /**
         * 自定义设备授权流（Device Authorization Grant）
         * 设备客户端身份验证转换器和提供器
         *
         * DeviceClientAuthenticationConverter：将设备授权请求转换为 Authentication 对象，用于设备认证。
         * - 设备授权流中，设备需要通过设备码进行身份验证。
         * - 这里的端点由 authorizationServerSettings.getDeviceAuthorizationEndpoint() 提供。
         * */
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
                new DeviceClientAuthenticationConverter(
                        authorizationServerSettings.getDeviceAuthorizationEndpoint());
        // DeviceClientAuthenticationProvider：实现设备客户端的认证逻辑，使用 RegisteredClientRepository 访问注册的客户端信息。
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
                new DeviceClientAuthenticationProvider(registeredClientRepository);


        /**
         * 设备授权端点配置
         */
        // @formatter:off
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                /**
                 * deviceAuthorizationEndpoint
                 * - 配置设备授权端点的验证 URI（即用户输入设备码的页面）
                 * - 这里将验证 URI 设置为 /activate
                 */
				.deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
						deviceAuthorizationEndpoint.verificationUri("/activate") // 此url位于：sample.web.DeviceController
				)
                /**
                 * deviceVerificationEndpoint
                 * - 配置设备验证端点的用户同意页面。
                 * - 自定义的同意页面路径通过 CUSTOM_CONSENT_PAGE_URI 提供
                 */
				.deviceVerificationEndpoint(deviceVerificationEndpoint ->
						deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI) // 此url位于：sample.web.AuthorizationConsentController.consent
				)
                /**
                 * 配置客户端身份认证
                 * 自定义客户端认证规则：
                 * - authenticationConverter：使用 deviceClientAuthenticationConverter 转换客户端请求。
                 * - authenticationProvider：使用 deviceClientAuthenticationProvider 验证客户端。
                 */
				.clientAuthentication(clientAuthentication ->
						clientAuthentication
								.authenticationConverter(deviceClientAuthenticationConverter)
								.authenticationProvider(deviceClientAuthenticationProvider)
				)
                /**
                 * 配置授权端点
                 * authorizationEndpoint：配置授权端点（如 /oauth2/authorize）的用户同意页面。
                 * - 使用自定义的同意页面路径 /oauth2/consent
                 */
				.authorizationEndpoint(authorizationEndpoint ->
						authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)) // 此url位于：sample.web.AuthorizationConsentController.consent
                // 启用 OpenID Connect 1.0 支持。
				.oidc(Customizer.withDefaults());
		// @formatter:on

        /**
         * 配置异常处理和资源服务器
         */
        // @formatter:off
		http
				.exceptionHandling((exceptions) -> exceptions
                        /**
                         * defaultAuthenticationEntryPointFor
                         * - 当用户未登录或认证失败时，处理异常的入口点。
                         * - 如果请求的 MediaType 是 text/html，将用户重定向到登录页面 /login。
                         */
						.defaultAuthenticationEntryPointFor(
								new LoginUrlAuthenticationEntryPoint("/login"),
								new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
						)
				)
                // 配置 OAuth2 资源服务器功能，支持基于 JWT 的令牌解析。
				.oauth2ResourceServer(oauth2ResourceServer ->
						oauth2ResourceServer.jwt(Customizer.withDefaults()));
		// @formatter:on
        /**
         * 返回过滤器链
         * - 构建并返回 SecurityFilterChain，应用到授权服务器的安全过滤器链中。
         */
        return http.build();
    }

    // 这个就是客户端的获取方式了，授权服务内部会调用做一些验证 例如 redirectUri
    // 官方给出的demo就先在内存里面初始化 也可以采用数据库的形式 实现 RegisteredClientRepository即可

    /**
     * 这段代码的作用是配置 OAuth2 的客户端存储库 RegisteredClientRepository，
     * 用于存储和管理已注册的 OAuth2 客户端信息。客户端可以使用多种授权方式（如授权码、客户端凭证等）与授权服务器进行交互。
     * <p>
     * RegisteredClientRepository：授权服务器用来管理 OAuth2 客户端的存储库接口。
     *
     * @param jdbcTemplate 通过 JDBC 操作数据库，用于存储客户端信息。
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        // 注册客户端配置：messaging-client
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString()) // 生成一个唯一的 ID，用于标识客户端
                // 客户端的唯一标识
                .clientId("messaging-client")
                // 客户端的密钥，授权服务器使用此密钥来验证客户端身份。 {noop} 表示客户端密钥未加密（仅用于开发环境，生产中建议加密存储）
                .clientSecret("{noop}secret")
                // 客户端认证方法，这里使用 Client Secret Basic，即客户端通过 HTTP Basic Authentication 发送 client_id 和 client_secret
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 支持的授权方式
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // 支持 授权码模式，常用于用户登录和授权场景
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 支持 刷新令牌模式，允许客户端使用刷新令牌获取新的访问令牌。
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // 支持 客户端凭证模式，用于服务端到服务端的授权。
                // 重定向 URI 和登出回调, OAuth2 授权服务器在完成授权后，回调到客户端的地址。
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc") // 用于 OpenID Connect 登录。 messaging-client-oidc 是自定义客户端的唯一标识，见yml文件，此url是自动生成的，授权服务器会将用户的授权结果（如授权码或错误信息）重定向到回调 URL： 授权服务器在处理客户端请求时，会检查 redirect_uri 是否在客户端注册时声明过。 如果 URL 不匹配，授权服务器会拒绝授权请求。
                .redirectUri("http://127.0.0.1:8080/authorized") // 通用的授权回调地址
                .postLogoutRedirectUri("http://127.0.0.1:8080/logged-out") // 设置用户登出后，跳转到客户端的页面
                // 授权范围（Scopes）
                .scope(OidcScopes.OPENID) // 启用 OpenID Connect，用于身份认证
                .scope(OidcScopes.PROFILE) // 请求访问用户的基本信息（如姓名、邮箱等）
                .scope("message.read") // 自定义的作用域，用于读取和写入消息
                .scope("message.write")
                // 客户端设置
                .clientSettings(
                        ClientSettings
                                .builder()
                                .requireAuthorizationConsent(true) // 强制用户在授权时显示同意页面,如果设置为 false，授权时将跳过用户同意页面（通常用于信任的客户端）
                                .build()
                )
                .build();

        // 注册客户端配置：device-messaging-client
        RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // 客户端的唯一标识
                .clientId("device-messaging-client")
                // 不需要客户端身份验证，适用于设备授权模式（Device Authorization Grant）
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                // 支持 设备授权模式，用于无界面设备（如电视、智能家居设备）登录。
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                // 支持使用刷新令牌续期访问令牌。
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // 自定义作用域 message.read 和 message.write
                .scope("message.read")
                .scope("message.write")
                .build();

        // Save registered client's in db as if in-memory
        // 保存到数据库
        // 创建 JdbcRegisteredClientRepository 实例，将客户端信息存储到数据库中。
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        // 调用 save 方法将 registeredClient 和 deviceClient 保存到数据库。
        registeredClientRepository.save(registeredClient);
        registeredClientRepository.save(deviceClient);

        // 返回 RegisteredClientRepository，供授权服务器使用。
        return registeredClientRepository;
    }
    // @formatter:on

    //这个是oauth2的授权信息(包含了用户、token等其他信息) 这个也是可以扩展的 OAuth2AuthorizationService也是一个实现类
    /**
     * 这段代码用于创建一个 OAuth2AuthorizationService 实例，负责管理 OAuth2 授权信息（如访问令牌、刷新令牌和设备授权信息等）。
     * 通过持久化存储的方式，授权信息可以被安全地保存到数据库中，并在后续的授权和认证过程中被查询和使用。
     * @param jdbcTemplate 一个简化的 JDBC 操作工具类，封装了常见的数据库访问逻辑。
     *                      作用：在 JdbcOAuth2AuthorizationService 中，用于执行数据库的 CRUD 操作（如保存、查询、删除授权信息）。
     * @param registeredClientRepository 管理和查询已注册的 OAuth2 客户端。
     *                                   - 当授权信息中涉及到客户端时，用于验证客户端的合法性。
     *                                   - 确保授权数据中的 client_id 对应的客户端在系统中是有效的。
     * @return
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 这个是oauth2授权记录的持久化存储方式 看 JdbcOAuth2AuthorizationConsentService 就知道是基于数据库的了,当然也可以进行扩展 基于redis 后面再讲， 你可以看看 JdbcOAuth2AuthorizationConsentService的是一个实现
     *
     * 创建一个 OAuth2AuthorizationConsentService 的实例，
     * 负责管理 用户对 OAuth2 客户端的授权同意信息（即用户授予客户端访问其资源的权限范围，称为 Scopes）。
     * 它基于数据库存储（JDBC），从而可以持久化用户的授权同意记录。
     * @param jdbcTemplate 使用 JDBC 的方式将授权同意记录存储到数据库中。
     * @param registeredClientRepository 客户端存储库，用于验证用户的授权同意信息中是否涉及合法的客户端。
     * @return
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                                                                         RegisteredClientRepository registeredClientRepository) {
        // Will be used by the ConsentController
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 定义了一个 OAuth2TokenCustomizer<JwtEncodingContext> Bean，用于对生成的 ID Token 进行自定义操作。
     * 具体来说，它通过实现自定义逻辑在 ID Token 中添加额外的声明（Claims）或修改已有的声明，以满足系统或业务的特殊需求。
     *
     * FederatedIdentityIdTokenCustomizer：
     * - 一个自定义的实现类，负责实现 ID Token 的自定义逻辑。
     *
     * 什么是 ID Token？
     * - ID Token 是 OpenID Connect (OIDC) 中的一个核心概念，它是一种 JWT（JSON Web Token），用于向客户端证明用户的身份信息。
     * - ID Token 通常包含以下内容：
     *  - iss (Issuer)：签发者。
     *  - sub (Subject)：用户的唯一标识符。
     *  - aud (Audience)：令牌的目标受众（客户端）。
     *  - exp 和 iat：令牌的过期时间和签发时间。
     *  - auth_time：用户完成身份验证的时间。
     * @return
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        return new FederatedIdentityIdTokenCustomizer();
    }

    /**
     * 定义了一个 JWKSource<SecurityContext> Bean，用于配置 JSON Web Key (JWK)，
     * 这是 OAuth 2.0 和 OpenID Connect (OIDC) 中用于签名和验证 JWT（JSON Web Token）的关键组件。
     * 通过生成和配置 RSA 密钥，这个 Bean 提供了一个签名和验证令牌的密钥集合。
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // 调用一个自定义工具类 Jwks 的方法 generateRsa() 来生成一个新的 RSA 密钥对
        RSAKey rsaKey = Jwks.generateRsa();
        // 将生成的 RSA 密钥包装为一个 JWK（JSON Web Key）
        JWKSet jwkSet = new JWKSet(rsaKey);
        // JWKSource 是一个接口，负责根据请求中的条件选择合适的密钥。
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * 定义了一个 JwtDecoder Bean，它是用于解码和验证 JSON Web Token (JWT) 的组件。
     * 它使用 JWK (JSON Web Key) 作为密钥来源，结合 OAuth2 的配置逻辑，确保令牌的完整性和可信性。
     * @param jwkSource
     * @return
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    //授权服务器的配置 很多class 你看它命名就知道了 想研究的可以点进去看一看

    /**
     * 定义了一个 Spring Bean，用于配置授权服务器（Authorization Server）的设置。
     * 通过使用 AuthorizationServerSettings.builder()，可以根据需求自定义授权服务器的行为和端点。
     * 这里使用Auth2.0默认的端点配置
     * @return
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


    //此时基于H2数据库(内存数据库) 需要使用mysql 就注释掉就可以了 demo这个地方我们用内存跑就行了 省事

    /**
     * 创建一个嵌入式数据库（Embedded Database）。嵌入式数据库适合用于开发和测试环境，提供了一种轻量级且易于设置的数据库支持。
     * @return
     */
    @Bean
    public EmbeddedDatabase embeddedDatabase() {
        // @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true) // 自动为嵌入式数据库生成一个唯一名称。
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
    }

}

