package com.redpanda.springoauth2jwtauthorizationserver.service.converter;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.AuthorizationConsent;
import java.util.HashSet;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
public class Oauth2AuthorizationConsentConverter
    implements DomainEntityBiConverter<OAuth2AuthorizationConsent, AuthorizationConsent> {

  private final RegisteredClientRepository registeredClientRepository;

  @Override
  public OAuth2AuthorizationConsent toDomain(AuthorizationConsent entity) {
    String registeredClientId = entity.getRegisteredClientId();
    RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
    if (registeredClient == null) {
      throw new DataRetrievalFailureException(
          "The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
    }

    OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(
        registeredClientId, entity.getPrincipalName());
    if (entity.getAuthorities() != null) {
      for (String authority : StringUtils.commaDelimitedListToSet(entity.getAuthorities())) {
        builder.authority(new SimpleGrantedAuthority(authority));
      }
    }

    return builder.build();
  }

  @Override
  public AuthorizationConsent toEntity(OAuth2AuthorizationConsent domain) {
    AuthorizationConsent entity = new AuthorizationConsent();
    entity.setRegisteredClientId(domain.getRegisteredClientId());
    entity.setPrincipalName(domain.getPrincipalName());

    Set<String> authorities = new HashSet<>();
    for (GrantedAuthority authority : domain.getAuthorities()) {
      authorities.add(authority.getAuthority());
    }
    entity.setAuthorities(StringUtils.collectionToCommaDelimitedString(authorities));

    return entity;
  }
}
