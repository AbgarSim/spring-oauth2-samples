package com.redpanda.springoauth2jwtauthorizationserver.service.converter;

import com.redpanda.springoauth2jwtauthorizationserver.security.CustomUserDetails;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.UserEntity;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsConverter
    implements DomainEntityBiConverter<CustomUserDetails, UserEntity> {
  @Override
  public CustomUserDetails toDomain(UserEntity entity) {

    return CustomUserDetails.builder()
        .id(entity.getId())
        .username(entity.getUsername())
        .password(entity.getPassword())
        .enabled(entity.isEnabled())
        .authorities(entity.getRoles().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet()))
        .build();
  }

  @Override
  public UserEntity toEntity(CustomUserDetails domain) {
    return UserEntity.builder()
        .id(domain.getId())
        .username(domain.getUsername())
        .password(domain.getPassword())
        .enabled(domain.isEnabled())
        .roles(domain.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()))
        .build();
  }
}
