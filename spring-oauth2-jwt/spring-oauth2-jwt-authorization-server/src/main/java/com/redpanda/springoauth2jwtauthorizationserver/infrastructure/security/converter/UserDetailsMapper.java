package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.converter;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.UserEntity;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.model.CustomUserDetails;
import java.util.Collection;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring")
public interface UserDetailsMapper {

  @Mapping(target = "authorities", expression = "java(mapRolesToAuthorities(userEntity.getRoles()))")
  CustomUserDetails fromEntityToDomain(UserEntity userEntity);

  @Mapping(target = "roles", expression = "java(mapAuthoritiesToRoles(userDetails.getAuthorities()))")
  UserEntity fromDomainToEntity(CustomUserDetails userDetails);

  default Set<GrantedAuthority> mapRolesToAuthorities(Set<String> roles) {
    return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
  }

  default Set<String> mapAuthoritiesToRoles(Collection<? extends GrantedAuthority> authorities) {
    return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
  }
}
