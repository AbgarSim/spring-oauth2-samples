package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository;


import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.UserEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserEntityRepository extends JpaRepository<UserEntity, Long> {
  UserEntity findByUsername(String username);
}

