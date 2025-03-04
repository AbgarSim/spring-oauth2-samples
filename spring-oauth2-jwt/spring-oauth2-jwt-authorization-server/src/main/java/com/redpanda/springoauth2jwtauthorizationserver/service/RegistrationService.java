package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.security.CustomUserDetails;
import com.redpanda.springoauth2jwtauthorizationserver.service.converter.UserDetailsConverter;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RegistrationService {
  private final EmailVerificationService emailVerificationService;
  private final UserDetailsManager userDetailsManager;

  @Transactional
  public void registerUser(String email, String password) {
    CustomUserDetails userDetails = CustomUserDetails.builder()
        .username(email)
        .password(password)
        .enabled(false)
        .authorities(Set.of(new SimpleGrantedAuthority("ROLE_USER")))
        .build();

    userDetailsManager.createUser(userDetails);

    if(!userDetails.isEnabled()) {
      emailVerificationService.sendVerificationTokenEmail(email);
    }
  }
}
