package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.repository;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.AuthorizationConsentEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorizationConsentEntityRepository extends JpaRepository<AuthorizationConsentEntity, Long> {
  Optional<AuthorizationConsentEntity> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
  void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
