package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.repository.RegisteredClientEntityRepository;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.converter.RegisteredClientMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

//@Service
@RequiredArgsConstructor
public class RegisteredClientRepositoryImpl implements RegisteredClientRepository {

  private final RegisteredClientEntityRepository registeredClientEntityRepository;

  private final RegisteredClientMapper registeredClientMapper;

  @Override
  public void save(RegisteredClient registeredClient) {
    registeredClientEntityRepository.save(registeredClientMapper.fromDomainToEntity(registeredClient));
  }

  @Override
  public RegisteredClient findById(String id) {
    return registeredClientEntityRepository.findById(id).map(registeredClientMapper::fromEntityToDomain)
        .orElse(null);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    return registeredClientEntityRepository.findByClientId(clientId).map(registeredClientMapper::fromEntityToDomain)
        .orElse(null);
  }
}
