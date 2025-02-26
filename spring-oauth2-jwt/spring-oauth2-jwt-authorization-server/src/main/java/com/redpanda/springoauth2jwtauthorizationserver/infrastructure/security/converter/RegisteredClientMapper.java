package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.converter;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.RegisteredClientEntity;
import java.util.Set;
import java.util.stream.Collectors;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Mapper(componentModel = "spring")
public interface RegisteredClientMapper {

  @Mapping(target = "grantTypes", expression = "java(mapGrantTypes(registeredClient))")
  @Mapping(target = "authenticationMethods", expression = "java(mapAuthenticationMethods(registeredClient))")
  RegisteredClientEntity fromDomainToEntity(RegisteredClient registeredClient);

  default RegisteredClient fromEntityToDomain(RegisteredClientEntity entity) {
    return RegisteredClient.withId(entity.getId())
        .clientId(entity.getClientId())
        .clientSecret(entity.getClientSecret())
        .authorizationGrantTypes(grantTypes ->
            entity.getGrantTypes().forEach(type -> grantTypes.add(new AuthorizationGrantType(type))))
        .clientAuthenticationMethods(authMethods ->
            entity.getAuthenticationMethods().forEach(method -> authMethods.add(new ClientAuthenticationMethod(method))))
        .scopes(scopes -> scopes.addAll(entity.getScopes()))
        .redirectUris(redirectUris -> redirectUris.addAll(entity.getRedirectUris()))
        .build();
  }

  // Convert AuthorizationGrantType to String
  default Set<String> mapGrantTypes(RegisteredClient registeredClient) {
    return registeredClient.getAuthorizationGrantTypes()
        .stream().map(AuthorizationGrantType::getValue).collect(Collectors.toSet());
  }

  // Convert String to AuthorizationGrantType
  default Set<AuthorizationGrantType> mapGrantTypes(RegisteredClientEntity entity) {
    return entity.getGrantTypes()
        .stream().map(AuthorizationGrantType::new).collect(Collectors.toSet());
  }

  // Convert ClientAuthenticationMethod to String
  default Set<String> mapAuthenticationMethods(RegisteredClient registeredClient) {
    return registeredClient.getClientAuthenticationMethods()
        .stream().map(ClientAuthenticationMethod::getValue).collect(Collectors.toSet());
  }

  // Convert String to ClientAuthenticationMethod
  default Set<ClientAuthenticationMethod> mapAuthenticationMethods(RegisteredClientEntity entity) {
    return entity.getAuthenticationMethods()
        .stream().map(ClientAuthenticationMethod::new).collect(Collectors.toSet());
  }
}
