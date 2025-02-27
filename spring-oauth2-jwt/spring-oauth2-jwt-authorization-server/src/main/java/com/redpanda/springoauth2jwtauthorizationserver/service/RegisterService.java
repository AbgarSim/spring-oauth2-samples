package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.model.CustomUserDetails;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

//@Service
@RequiredArgsConstructor
public class RegisterService {

  private final UserDetailsServiceImpl userDetailsService;


  @Transactional
  public void registerUser(String username, String password) {
    CustomUserDetails userDetails = CustomUserDetails.builder()
        .username(username)
        .password(password)
        .authorities(Set.of(new SimpleGrantedAuthority("ROLE_USER")))
        .build();
    userDetailsService.createUser(userDetails);
  }
}
