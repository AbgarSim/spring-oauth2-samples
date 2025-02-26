package com.redpanda.springoauth2jwtauthorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    // Set the allowed origins. In production, specify your front-end domain(s).
    configuration.setAllowedOrigins(List.of("http://localhost:8083", "https://my-frontend.com"));
    // You can allow all origins for development, but be careful in production:
    // configuration.setAllowedOriginPatterns(List.of("*"));

    // Allowed HTTP methods (POST, GET, etc.)
    configuration.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));

    // Allowed headers
    configuration.setAllowedHeaders(List.of("Content-Type","Authorization"));

    // If you need credentials (cookies, tokens) to be included
    configuration.setAllowCredentials(true);

    // Apply this configuration to any endpoint path
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {
    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
        OAuth2AuthorizationServerConfigurer.authorizationServer();

    http
        .cors(Customizer.withDefaults())
        .csrf().disable()
        .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
        .with(authorizationServerConfigurer, (authorizationServer) ->
            authorizationServer
                .oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
        )
        .authorizeHttpRequests((authorize) ->
            authorize
                .anyRequest().authenticated()
        )
        // Redirect to the login page when not authenticated from the
        // authorization endpoint
        .exceptionHandling((exceptions) -> exceptions
            .defaultAuthenticationEntryPointFor(
                new LoginUrlAuthenticationEntryPoint("/login"),
                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
            )
        );

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
      throws Exception {
    http
        .authorizeHttpRequests((authorize) -> authorize
            .anyRequest().authenticated()
        )
        // Form login handles the redirect to the login page from the
        // authorization server filter chain
        .formLogin(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

}


/**
 * //  @Bean
 * //  public RegisteredClientRepository registeredClientRepository() {
 * //    RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
 * //        .clientId("sample-client")
 * //        .clientSecret("{noop}secret")
 * //        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
 * //        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
 * //        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
 * //        .redirectUri("http://localhost:8083/callback.html")
 * //        .redirectUri("com.sample.app://callback")
 * //        .postLogoutRedirectUri("http://localhost:8083/")
 * //        .scope(OidcScopes.OPENID)
 * //        .scope("read")
 * //        .scope(OidcScopes.PROFILE)
 * //        .clientSettings(
 * //            ClientSettings.builder()
 * //                .requireProofKey(true)
 * //                .requireAuthorizationConsent(true)
 * //                .build()
 * //        )
 * //        .build();
 * //
 * //    return new InMemoryRegisteredClientRepository(oidcClient);
 * //  } @Bean
 *   public UserDetailsService userDetailsService() {
 *     UserDetails userDetails = User.withDefaultPasswordEncoder()
 *         .username("user")
 *         .password("password")
 *         .roles("USER")
 *         .build();
 *
 *     return new InMemoryUserDetailsManager(userDetails);
 *   }
 */