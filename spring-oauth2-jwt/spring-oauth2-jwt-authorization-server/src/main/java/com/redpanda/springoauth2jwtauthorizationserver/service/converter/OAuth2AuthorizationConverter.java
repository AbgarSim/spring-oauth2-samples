package com.redpanda.springoauth2jwtauthorizationserver.service.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.Authorization;
import java.time.Instant;
import java.util.Map;
import java.util.function.Consumer;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class OAuth2AuthorizationConverter
    implements DomainEntityBiConverter<OAuth2Authorization, Authorization> {

  private final RegisteredClientRepository registeredClientRepository;
  private final ObjectMapper objectMapper;

  private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.AUTHORIZATION_CODE;
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.CLIENT_CREDENTIALS;
    } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.REFRESH_TOKEN;
    } else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.DEVICE_CODE;
    }
    return new AuthorizationGrantType(authorizationGrantType);
  }

  @Override
  public OAuth2Authorization toDomain(Authorization entity) {
    RegisteredClient registeredClient = this.registeredClientRepository.findById(entity.getRegisteredClientId());
    if (registeredClient == null) {
      throw new DataRetrievalFailureException(
          "The RegisteredClient with id '" + entity.getRegisteredClientId() +
              "' was not found in the RegisteredClientRepository.");
    }

    OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
        .id(entity.getId())
        .principalName(entity.getPrincipalName())
        .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
        .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
        .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));
    if (entity.getState() != null) {
      builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
    }

    if (entity.getAuthorizationCodeValue() != null) {
      OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
          entity.getAuthorizationCodeValue(),
          entity.getAuthorizationCodeIssuedAt(),
          entity.getAuthorizationCodeExpiresAt());
      builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
    }

    if (entity.getAccessTokenValue() != null) {
      OAuth2AccessToken accessToken = new OAuth2AccessToken(
          OAuth2AccessToken.TokenType.BEARER,
          entity.getAccessTokenValue(),
          entity.getAccessTokenIssuedAt(),
          entity.getAccessTokenExpiresAt(),
          StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
      builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
    }

    if (entity.getRefreshTokenValue() != null) {
      OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
          entity.getRefreshTokenValue(),
          entity.getRefreshTokenIssuedAt(),
          entity.getRefreshTokenExpiresAt());
      builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
    }

    if (entity.getOidcIdTokenValue() != null) {
      OidcIdToken idToken = new OidcIdToken(
          entity.getOidcIdTokenValue(),
          entity.getOidcIdTokenIssuedAt(),
          entity.getOidcIdTokenExpiresAt(),
          parseMap(entity.getOidcIdTokenClaims()));
      builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
    }

    if (entity.getUserCodeValue() != null) {
      OAuth2UserCode userCode = new OAuth2UserCode(
          entity.getUserCodeValue(),
          entity.getUserCodeIssuedAt(),
          entity.getUserCodeExpiresAt());
      builder.token(userCode, metadata -> metadata.putAll(parseMap(entity.getUserCodeMetadata())));
    }

    if (entity.getDeviceCodeValue() != null) {
      OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
          entity.getDeviceCodeValue(),
          entity.getDeviceCodeIssuedAt(),
          entity.getDeviceCodeExpiresAt());
      builder.token(deviceCode, metadata -> metadata.putAll(parseMap(entity.getDeviceCodeMetadata())));
    }

    return builder.build();
  }

  @Override
  public Authorization toEntity(OAuth2Authorization domain) {
    Authorization entity = new Authorization();
    entity.setId(domain.getId());
    entity.setRegisteredClientId(domain.getRegisteredClientId());
    entity.setPrincipalName(domain.getPrincipalName());
    entity.setAuthorizationGrantType(domain.getAuthorizationGrantType().getValue());
    entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(domain.getAuthorizedScopes(), ","));
    entity.setAttributes(writeMap(domain.getAttributes()));
    entity.setState(domain.getAttribute(OAuth2ParameterNames.STATE));

    OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
        domain.getToken(OAuth2AuthorizationCode.class);
    setTokenValues(
        authorizationCode,
        entity::setAuthorizationCodeValue,
        entity::setAuthorizationCodeIssuedAt,
        entity::setAuthorizationCodeExpiresAt,
        entity::setAuthorizationCodeMetadata
    );

    OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
        domain.getToken(OAuth2AccessToken.class);
    setTokenValues(
        accessToken,
        entity::setAccessTokenValue,
        entity::setAccessTokenIssuedAt,
        entity::setAccessTokenExpiresAt,
        entity::setAccessTokenMetadata
    );
    if (accessToken != null && accessToken.getToken().getScopes() != null) {
      entity.setAccessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
    }

    OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
        domain.getToken(OAuth2RefreshToken.class);
    setTokenValues(
        refreshToken,
        entity::setRefreshTokenValue,
        entity::setRefreshTokenIssuedAt,
        entity::setRefreshTokenExpiresAt,
        entity::setRefreshTokenMetadata
    );

    OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
        domain.getToken(OidcIdToken.class);
    setTokenValues(
        oidcIdToken,
        entity::setOidcIdTokenValue,
        entity::setOidcIdTokenIssuedAt,
        entity::setOidcIdTokenExpiresAt,
        entity::setOidcIdTokenMetadata
    );
    if (oidcIdToken != null) {
      entity.setOidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
    }

    OAuth2Authorization.Token<OAuth2UserCode> userCode =
        domain.getToken(OAuth2UserCode.class);
    setTokenValues(
        userCode,
        entity::setUserCodeValue,
        entity::setUserCodeIssuedAt,
        entity::setUserCodeExpiresAt,
        entity::setUserCodeMetadata
    );

    OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
        domain.getToken(OAuth2DeviceCode.class);
    setTokenValues(
        deviceCode,
        entity::setDeviceCodeValue,
        entity::setDeviceCodeIssuedAt,
        entity::setDeviceCodeExpiresAt,
        entity::setDeviceCodeMetadata
    );

    return entity;
  }

  private void setTokenValues(
      OAuth2Authorization.Token<?> token,
      Consumer<String> tokenValueConsumer,
      Consumer<Instant> issuedAtConsumer,
      Consumer<Instant> expiresAtConsumer,
      Consumer<String> metadataConsumer) {
    if (token != null) {
      OAuth2Token oAuth2Token = token.getToken();
      tokenValueConsumer.accept(oAuth2Token.getTokenValue());
      issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
      expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
      metadataConsumer.accept(writeMap(token.getMetadata()));
    }
  }

  private Map<String, Object> parseMap(String data) {
    try {
      return this.objectMapper.readValue(data, new TypeReference<>() {
      });
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private String writeMap(Map<String, Object> metadata) {
    try {
      return this.objectMapper.writeValueAsString(metadata);
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }
}
