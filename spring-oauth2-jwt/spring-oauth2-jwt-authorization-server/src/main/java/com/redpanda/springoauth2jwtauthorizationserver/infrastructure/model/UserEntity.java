package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model;

import jakarta.persistence.*;
import java.util.Set;
import lombok.*;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Table(name = "users")
public class UserEntity {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(unique = true, nullable = false)
  private String username;

  private String password;

  private boolean enabled;

  @ElementCollection(fetch = FetchType.EAGER)
  private Set<String> roles;
}

