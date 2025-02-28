package com.redpanda.springoauth2jwtauthorizationserver.service.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.Client;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class RegisteredClientConverter
    implements DomainEntityBiConverter<RegisteredClient, Client> {

  private final ObjectMapper objectMapper;

  private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.AUTHORIZATION_CODE;
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.CLIENT_CREDENTIALS;
    } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.REFRESH_TOKEN;
    }
    return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
  }

  private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
    if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
      return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
    } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
      return ClientAuthenticationMethod.CLIENT_SECRET_POST;
    } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
      return ClientAuthenticationMethod.NONE;
    }
    return new ClientAuthenticationMethod(clientAuthenticationMethod);      // Custom client authentication method
  }

  @Override
  public RegisteredClient toDomain(Client entity) {
    Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(
        entity.getClientAuthenticationMethods());
    Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(
        entity.getAuthorizationGrantTypes());
    Set<String> redirectUris = StringUtils.commaDelimitedListToSet(
        entity.getRedirectUris());
    Set<String> postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(
        entity.getPostLogoutRedirectUris());
    Set<String> clientScopes = StringUtils.commaDelimitedListToSet(
        entity.getScopes());

    RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId())
        .clientId(entity.getClientId())
        .clientIdIssuedAt(entity.getClientIdIssuedAt())
        .clientSecret(entity.getClientSecret())
        .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
        .clientName(entity.getClientName())
        .clientAuthenticationMethods(authenticationMethods ->
            clientAuthenticationMethods.forEach(authenticationMethod ->
                authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
        .authorizationGrantTypes((grantTypes) ->
            authorizationGrantTypes.forEach(grantType ->
                grantTypes.add(resolveAuthorizationGrantType(grantType))))
        .redirectUris((uris) -> uris.addAll(redirectUris))
        .postLogoutRedirectUris((uris) -> uris.addAll(postLogoutRedirectUris))
        .scopes((scopes) -> scopes.addAll(clientScopes));

    Map<String, Object> clientSettingsMap = parseMap(entity.getClientSettings());
    builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

    Map<String, Object> tokenSettingsMap = parseMap(entity.getTokenSettings());
    builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

    return builder.build();
  }

  @Override
  public Client toEntity(RegisteredClient domain) {
    List<String> clientAuthenticationMethods = new ArrayList<>(domain.getClientAuthenticationMethods().size());
    domain.getClientAuthenticationMethods().forEach(clientAuthenticationMethod ->
        clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

    List<String> authorizationGrantTypes = new ArrayList<>(domain.getAuthorizationGrantTypes().size());
    domain.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
        authorizationGrantTypes.add(authorizationGrantType.getValue()));

    Client entity = new Client();
    entity.setId(domain.getId());
    entity.setClientId(domain.getClientId());
    entity.setClientIdIssuedAt(domain.getClientIdIssuedAt());
    entity.setClientSecret(domain.getClientSecret());
    entity.setClientSecretExpiresAt(domain.getClientSecretExpiresAt());
    entity.setClientName(domain.getClientName());
    entity.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
    entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
    entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(domain.getRedirectUris()));
    entity.setPostLogoutRedirectUris(StringUtils.collectionToCommaDelimitedString(domain.getPostLogoutRedirectUris()));
    entity.setScopes(StringUtils.collectionToCommaDelimitedString(domain.getScopes()));
    entity.setClientSettings(writeMap(domain.getClientSettings().getSettings()));
    entity.setTokenSettings(writeMap(domain.getTokenSettings().getSettings()));

    return entity;
  }

  private Map<String, Object> parseMap(String data) {
    try {
      Map<String, Object> parsedMap = this.objectMapper.readValue(data, new TypeReference<>() {
      });
      return parsedMap.entrySet().stream().
          map(e -> {
            if (e.getKey().contains("time-to")) {
              e.setValue(Duration.of(((Double) e.getValue()).longValue(), ChronoUnit.SECONDS));
            } else if (e.getKey().contains("token-format")) {
              String value = String.valueOf(((Map<String, String>) e.getValue()).get("value"));
              if (value.equals(OAuth2TokenFormat.SELF_CONTAINED.getValue())) {
                e.setValue(OAuth2TokenFormat.SELF_CONTAINED);
              } else if (value.equals(OAuth2TokenFormat.REFERENCE.getValue())) {
                e.setValue(OAuth2TokenFormat.REFERENCE);
              } else {
                e.setValue(e.getValue());
              }
            }
            return e;
          }).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private String writeMap(Map<String, Object> data) {
    try {
      return this.objectMapper.writeValueAsString(data);
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }
}
