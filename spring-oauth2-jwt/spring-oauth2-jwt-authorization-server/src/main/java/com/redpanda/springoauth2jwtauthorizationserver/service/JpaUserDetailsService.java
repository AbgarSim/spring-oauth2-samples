package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.security.CustomUserDetails;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.UserEntity;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository.UserEntityRepository;
import com.redpanda.springoauth2jwtauthorizationserver.service.converter.UserDetailsConverter;
import jakarta.annotation.PostConstruct;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsManager, UserDetailsPasswordService {

  private final UserEntityRepository userEntityRepository;
  private final UserDetailsConverter userDetailsConverter;
  private final PasswordEncoder passwordEncoder;

  @PostConstruct
  public void init() {
    if (userEntityRepository.findAll().isEmpty()) {
      CustomUserDetails userDetails = CustomUserDetails.builder()
          .username("user")
          .password(passwordEncoder.encode("password"))
          .enabled(true)
          .authorities(Set.of(new SimpleGrantedAuthority("ROLE_USER")))
          .build();
      userEntityRepository.save(userDetailsConverter.toEntity(userDetails));
    }
  }

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    UserEntity user = userEntityRepository.findByUsername(username);
    if (user == null) {
      throw new UsernameNotFoundException("User not found: " + username);
    }
    return userDetailsConverter.toDomain(user);
  }

  @Override
  @Transactional
  public void createUser(UserDetails userDetails) {
    if (userEntityRepository.findByUsername(userDetails.getUsername()) != null) {
      throw new IllegalArgumentException("User already exists: " + userDetails.getUsername());
    }
    UserEntity user = userDetailsConverter.toEntity((CustomUserDetails) userDetails);
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    userEntityRepository.save(user);
  }

  @Override
  @Transactional
  public void updateUser(UserDetails userDetails) {
    UserEntity existingUser = userEntityRepository.findByUsername(userDetails.getUsername());
    if (existingUser == null) {
      throw new UsernameNotFoundException("User not found: " + userDetails.getUsername());
    }
    UserEntity updatedUser = userDetailsConverter.toEntity((CustomUserDetails) userDetails);
    updatedUser.setId(existingUser.getId());
    if (!userDetails.getPassword().equals(existingUser.getPassword())) {
      updatedUser.setPassword(passwordEncoder.encode(existingUser.getPassword()));
    } else {
      updatedUser.setPassword(existingUser.getPassword());
    }
    userEntityRepository.save(updatedUser);
  }

  @Override
  @Transactional
  public void deleteUser(String username) {
    UserEntity user = userEntityRepository.findByUsername(username);
    if (user != null) {
      userEntityRepository.delete(user);
    }
  }

  @Override
  public void changePassword(String oldPassword, String newPassword) {
    throw new UnsupportedOperationException("Not implemented yet");
  }

  @Override
  @Transactional
  public boolean userExists(String username) {
    return userEntityRepository.findByUsername(username) != null;
  }

  @Override
  @Transactional
  public UserDetails updatePassword(UserDetails user, String newPassword) {
    UserEntity existingUser = userEntityRepository.findByUsername(user.getUsername());
    if (existingUser == null) {
      throw new UsernameNotFoundException("User not found: " + user.getUsername());
    }
    existingUser.setPassword(passwordEncoder.encode(newPassword));
    userEntityRepository.save(existingUser);
    return userDetailsConverter.toDomain(existingUser);
  }
}
