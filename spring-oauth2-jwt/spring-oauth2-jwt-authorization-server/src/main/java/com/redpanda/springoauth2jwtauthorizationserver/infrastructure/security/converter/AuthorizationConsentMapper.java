package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.converter;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.AuthorizationConsentEntity;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;

@Mapper(componentModel = "spring")
public interface AuthorizationConsentMapper {

  default OAuth2AuthorizationConsent fromEntityToDomain(AuthorizationConsentEntity entity) {
    return OAuth2AuthorizationConsent.withId(entity.getRegisteredClientId(), entity.getPrincipalName())
        .authorities(authorities -> entity.getAuthorities().forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth))))
        .build();
  }


  @Mapping(target = "id", source = "registeredClientId")
  @Mapping(target = "principalName", source = "principalName")
  @Mapping(target = "authorities", expression = "java(mapAuthorities(consent))")
  AuthorizationConsentEntity fromDomainToEntity(OAuth2AuthorizationConsent consent);

  default Set<String> mapAuthorities(Set<String> authorities) {
    return new HashSet<>(authorities);
  }

  default Set<String> mapAuthorities(OAuth2AuthorizationConsent consent) {
    return consent.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toSet());
  }
}
