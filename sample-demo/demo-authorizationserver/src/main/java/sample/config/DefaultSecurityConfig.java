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

import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import sample.federation.FederatedIdentityAuthenticationSuccessHandler;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * 主要用于配置Spring Security的 默认安全设置，包括允许访问的URL、禁用CSRF保护、配置表单登录和OAuth2登录等。
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 1.1
 */
@EnableWebSecurity // 启用Spring Security的功能，也就是配置Spring Security的默认安全配置。
@Configuration(proxyBeanMethods = false) // 表示这个类是一个配置类，并且不会代理bean方法。
public class DefaultSecurityConfig {

    // 过滤器链
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize ->//① 配置鉴权的
                        authorize
                                .requestMatchers("/assets/**", "/webjars/**", "/login", "/oauth2/**", "/oauth2/token").permitAll() //② 忽略鉴权的url
                                .anyRequest().authenticated()//③ 排除忽略的其他url就需要鉴权了
                )
                .csrf(AbstractHttpConfigurer::disable) // 禁用CSRF保护， CSRF 是一种防护机制，用于防止恶意网站通过伪造用户请求进行操作。如果 API 是无状态或使用了其他方式保护（如 JWT），通常禁用 CSRF。
                .formLogin(formLogin -> // 配置表单登录
                        formLogin
                                .loginPage("/login")//④ 授权服务认证页面（可以配置相对和绝对地址，前后端分离的情况下填前端的url）
                )
                .oauth2Login(oauth2Login -> // 配置OAuth2登录
                        oauth2Login
                                .loginPage("/login")//⑤ oauth2的认证页面（也可配置绝对地址），与表单登录共享同一个登录页面。
                                // 指定登录成功后的处理逻辑。这里调用了自定义的 authenticationSuccessHandler 方法
                                .successHandler(authenticationSuccessHandler())//⑥ 登录成功后的处理
                );

        return http.build();
    }


    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new FederatedIdentityAuthenticationSuccessHandler();
    }

    // 初始化了一个用户在内存里面（这样就不会每次启动就再去生成密码了）
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user1")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }


    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }


    /**
     * 跨域过滤器配置
     *
     * @return
     */
    @Bean
    public CorsFilter corsFilter() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*");
        configuration.setAllowCredentials(true);
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
        configurationSource.registerCorsConfiguration("/**", configuration);
        return new CorsFilter(configurationSource);
    }

}
