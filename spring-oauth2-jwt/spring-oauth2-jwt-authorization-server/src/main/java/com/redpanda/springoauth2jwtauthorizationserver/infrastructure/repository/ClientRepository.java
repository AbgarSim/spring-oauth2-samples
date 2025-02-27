package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.Client;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
  Optional<Client> findByClientId(String clientId);
}
