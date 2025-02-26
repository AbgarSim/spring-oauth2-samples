package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model;

import jakarta.persistence.*;
import java.util.Set;
import java.util.UUID;
import lombok.*;
import lombok.experimental.Accessors;

@Data
@Entity
@Table(name = "registered_client")
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class RegisteredClientEntity {

  @Id
  private String id = UUID.randomUUID().toString();

  @Column(unique = true, nullable = false)
  private String clientId;

  private String clientSecret;

  @ElementCollection(fetch = FetchType.EAGER)
  private Set<String> scopes;

  @ElementCollection(fetch = FetchType.EAGER)
  private Set<String> redirectUris;

  @ElementCollection(fetch = FetchType.EAGER)
  private Set<String> grantTypes;

  @ElementCollection(fetch = FetchType.EAGER)
  private Set<String> authenticationMethods;
}