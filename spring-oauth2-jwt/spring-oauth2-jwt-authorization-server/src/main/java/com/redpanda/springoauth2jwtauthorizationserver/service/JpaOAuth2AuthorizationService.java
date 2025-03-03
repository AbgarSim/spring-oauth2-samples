package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.Authorization;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository.AuthorizationRepository;
import com.redpanda.springoauth2jwtauthorizationserver.service.converter.OAuth2AuthorizationConverter;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {
  private final AuthorizationRepository authorizationRepository;
  private final OAuth2AuthorizationConverter oAuth2AuthorizationConverter;

  @Override
  public void save(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    this.authorizationRepository.save(oAuth2AuthorizationConverter.toEntity(authorization));
  }

  @Override
  public void remove(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    this.authorizationRepository.deleteById(authorization.getId());
  }

  @Override
  public OAuth2Authorization findById(String id) {
    Assert.hasText(id, "id cannot be empty");
    return this.authorizationRepository.findById(id).map(oAuth2AuthorizationConverter::toDomain).orElse(null);
  }

  @Override
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    Assert.hasText(token, "token cannot be empty");

    Optional<Authorization> result;
    if (tokenType == null) {
      result = this.authorizationRepository.findAnyToken(token);
    } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
      result = this.authorizationRepository.findByState(token);
    } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
      result = this.authorizationRepository.findByAuthorizationCodeValue(token);
    } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
      result = this.authorizationRepository.findByAccessTokenValue(token);
    } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
      result = this.authorizationRepository.findByRefreshTokenValue(token);
    } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
      result = this.authorizationRepository.findByOidcIdTokenValue(token);
    } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
      result = this.authorizationRepository.findByUserCodeValue(token);
    } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
      result = this.authorizationRepository.findByDeviceCodeValue(token);
    } else {
      result = Optional.empty();
    }

    return result.map(oAuth2AuthorizationConverter::toDomain).orElse(null);
  }
}
