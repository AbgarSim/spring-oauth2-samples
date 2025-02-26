package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.service;


import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.repository.AuthorizationConsentEntityRepository;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.converter.AuthorizationConsentMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;


@Component
@RequiredArgsConstructor
public class OAuth2AuthorizationConsentServiceImpl implements OAuth2AuthorizationConsentService {

  private final AuthorizationConsentEntityRepository authorizationConsentRepository;

  private final AuthorizationConsentMapper authorizationConsentMapper;

  @Override
  public void save(OAuth2AuthorizationConsent authorizationConsent) {
    Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
    this.authorizationConsentRepository.save(authorizationConsentMapper.fromDomainToEntity(authorizationConsent));
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
        registeredClientId, principalName).map(authorizationConsentMapper::fromEntityToDomain).orElse(null);
  }
}

