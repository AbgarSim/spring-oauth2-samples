package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.repository;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.RegisteredClientEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RegisteredClientEntityRepository extends JpaRepository<RegisteredClientEntity, String> {
  Optional<RegisteredClientEntity> findByClientId(String clientId);
}
