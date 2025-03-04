package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository;


import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.VerificationToken;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
  Optional<VerificationToken> findByToken(String token);
}
