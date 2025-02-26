package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model;

import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import lombok.Data;

@Data
@Entity
@Table(name = "authorization_consent")
public class AuthorizationConsentEntity {

  @Id
  private String id = UUID.randomUUID().toString();

  @Column(nullable = false)
  private String registeredClientId;

  @Column(nullable = false)
  private String principalName;

  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name = "oauth2_authorization_consent_scopes", joinColumns = @JoinColumn(name = "authorization_consent_id"))
  @Column(name = "scope")
  private Set<String> authorities = new HashSet<>();
}
