package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository.ClientRepository;
import com.redpanda.springoauth2jwtauthorizationserver.service.converter.RegisteredClientConverter;
import jakarta.annotation.PostConstruct;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
public class JpaRegisteredClientRepository implements RegisteredClientRepository {
  private final ClientRepository clientRepository;
  private final RegisteredClientConverter registeredClientConverter;
  private final PasswordEncoder passwordEncoder;

  @PostConstruct
  public void init() {
    if (clientRepository.findAll().isEmpty()) {
      RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
          .clientId("sample-client")
          .clientSecret(passwordEncoder.encode("secret"))
          .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
          .redirectUri("http://localhost:8083/callback.html")
          .redirectUri("com.sample.app://callback")
          .postLogoutRedirectUri("http://localhost:8083/")
          .scope(OidcScopes.OPENID)
          .scope("read")
          .scope(OidcScopes.PROFILE)
          .clientSettings(
              ClientSettings.builder()
                  .requireProofKey(true)
                  .requireAuthorizationConsent(true)
                  .build()
          )
          .build();
      clientRepository.save(registeredClientConverter.toEntity(oidcClient));
    }
  }


  @Override
  public void save(RegisteredClient registeredClient) {
    Assert.notNull(registeredClient, "registeredClient cannot be null");
    this.clientRepository.save(registeredClientConverter.toEntity(registeredClient));
  }

  @Override
  public RegisteredClient findById(String id) {
    Assert.hasText(id, "id cannot be empty");
    return this.clientRepository.findById(id).map(registeredClientConverter::toDomain).orElse(null);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    Assert.hasText(clientId, "clientId cannot be empty");
    return this.clientRepository.findByClientId(clientId).map(registeredClientConverter::toDomain).orElse(null);
  }
}
