package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.AuthorizationEntity;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.repository.AuthorizationEntityRepository;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.converter.AuthorizationMapper;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

//@Service
@RequiredArgsConstructor
public class AuthorizationServiceImpl implements OAuth2AuthorizationService {

  private final AuthorizationEntityRepository authorizationEntityRepository;

  private final AuthorizationMapper authorizationMapper;

  @Override
  public void save(OAuth2Authorization authorization) {
    authorizationEntityRepository.save(authorizationMapper.domainToEntity(authorization));
  }

  @Override
  public void remove(OAuth2Authorization authorization) {
    authorizationEntityRepository.delete(authorizationMapper.domainToEntity(authorization));
  }

  @Override
  public OAuth2Authorization findById(String id) {
    return authorizationEntityRepository.findById(id).map(authorizationMapper::entityToDomain).orElse(null);
  }

  @Override
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    String tokenTypeStr = tokenType != null ? tokenType.getValue() : "";

    Optional<AuthorizationEntity> result = switch (tokenTypeStr) {
      case OAuth2ParameterNames.STATE -> this.authorizationEntityRepository.findByState(token);
      case OAuth2ParameterNames.CODE -> this.authorizationEntityRepository.findByAuthorizationCodeValue(token);
      case OAuth2ParameterNames.ACCESS_TOKEN -> this.authorizationEntityRepository.findByAccessTokenValue(token);
      case OAuth2ParameterNames.REFRESH_TOKEN -> this.authorizationEntityRepository.findByRefreshTokenValue(token);
      case OidcParameterNames.ID_TOKEN -> this.authorizationEntityRepository.findByOidcIdTokenValue(token);
      case OAuth2ParameterNames.USER_CODE -> this.authorizationEntityRepository.findByUserCodeValue(token);
      case OAuth2ParameterNames.DEVICE_CODE -> this.authorizationEntityRepository.findByDeviceCodeValue(token);
      default -> this.authorizationEntityRepository.findByAnyToken(token);
    };

    return result.map(authorizationMapper::entityToDomain).orElse(null);
  }
}
