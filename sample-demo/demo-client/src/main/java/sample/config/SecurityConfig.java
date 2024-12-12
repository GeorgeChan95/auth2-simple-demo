package sample.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * @author Joe Grandja
 * @author Dmitriy Dubson
 * @author Steve Riesenberg
 * @since 0.0.1
 */
@EnableWebSecurity // 启用 Spring Security 的 Web 安全特性，允许我们通过 SecurityFilterChain 自定义安全策略。
@Configuration(proxyBeanMethods = false) // proxyBeanMethods = false 表示 Spring 不会对该配置类创建代理，提高性能。
public class SecurityConfig {

	/**
	 * 配置 Spring Security 忽略某些静态资源的安全过滤。
	 * @return
	 */
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return (web) -> web.ignoring().requestMatchers("/webjars/**", "/assets/**");
	}

	// @formatter:off

	/**
	 * Spring Security 的核心配置方法，用于定义 HTTP 请求的安全规则和认证方式
	 * @param http
	 * @param clientRegistrationRepository
	 * @return
	 * @throws Exception
	 */
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http,
			ClientRegistrationRepository clientRegistrationRepository) throws Exception {
		http
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/logged-out").permitAll() // 对该路径的请求不需要认证，任何人都可以访问。
					.anyRequest().authenticated() // 其他请求需要认证（用户必须登录后才能访问）。
			)
			.csrf(AbstractHttpConfigurer::disable) // 禁用跨站请求伪造 (CSRF) 防护,适用于 RESTful APIs 或不需要表单提交的场景
			.oauth2Login(withDefaults()) // 启用 OAuth2 登录功能, Spring Security 会根据配置的 ClientRegistration 自动生成登录页面，并处理 OAuth2 登录流程
			.oauth2Client(withDefaults()) // 启用 OAuth2 客户端支持，用于发起对外部服务的 OAuth2 认证请求。
			.logout(logout -> // 配置登出成功后的行为，使用了自定义的 oidcLogoutSuccessHandler() 方法
				logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));
		return http.build();
	}
	// @formatter:on

	/**
	 * 核心类: OidcClientInitiatedLogoutSuccessHandler
	 * - 专门处理 OpenID Connect (OIDC) 的登出逻辑。
	 * - 允许应用通知 OpenID Provider (OP) 执行登出操作，并在登出后跳转到指定的页面。
	 * @param clientRegistrationRepository
	 * @return
	 */
	private LogoutSuccessHandler oidcLogoutSuccessHandler(
			ClientRegistrationRepository clientRegistrationRepository) {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
				new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);

		// Set the location that the End-User's User Agent will be redirected to
		// after the logout has been performed at the Provider
		oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/logged-out");

		return oidcLogoutSuccessHandler;
	}

}
