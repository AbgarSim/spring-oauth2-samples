package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository.AuthorizationConsentRepository;
import com.redpanda.springoauth2jwtauthorizationserver.service.converter.Oauth2AuthorizationConsentConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {
  private final AuthorizationConsentRepository authorizationConsentRepository;
  private final Oauth2AuthorizationConsentConverter oauth2AuthorizationConsentConverter;


  @Override
  public void save(OAuth2AuthorizationConsent authorizationConsent) {
    Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
    this.authorizationConsentRepository.save(oauth2AuthorizationConsentConverter.toEntity(authorizationConsent));
  }

  @Override
  public void remove(OAuth2AuthorizationConsent authorizationConsent) {
    Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
    this.authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
        authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
  }

  @Override
  public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
    Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
    Assert.hasText(principalName, "principalName cannot be empty");
    return this.authorizationConsentRepository.findByRegisteredClientIdAndPrincipalName(
        registeredClientId, principalName).map(oauth2AuthorizationConsentConverter::toDomain).orElse(null);
  }
}
