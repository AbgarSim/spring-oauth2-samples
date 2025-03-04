package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.UserEntity;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.VerificationToken;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository.UserEntityRepository;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository.VerificationTokenRepository;
import com.redpanda.springoauth2jwtauthorizationserver.service.converter.UserDetailsConverter;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

  private final EmailService emailService;

  private final VerificationTokenRepository tokenRepository;
  private final UserEntityRepository userEntityRepository;

  private final UserDetailsManager userDetailsManager;

  private final UserDetailsConverter userDetailsConverter;


  @Transactional
  public void sendVerificationTokenEmail(String email) {
    String token = UUID.randomUUID().toString();
    VerificationToken verificationToken = new VerificationToken();
    verificationToken.setToken(token);
    verificationToken.setUserEmail(email);
    verificationToken.setExpiryDate(LocalDateTime.now().plusHours(24)); // 24h expiry

    tokenRepository.save(verificationToken);

    // Send Verification Email
    String verificationUrl = "http://localhost:9001/verify-email?token=" + token;
    emailService.sendEmail(email, "Verify Your Email", "Click here to verify: " + verificationUrl);

  }

  public boolean verifyToken(String token) {
    Optional<VerificationToken> verificationToken = tokenRepository.findByToken(token);
    if (verificationToken.isPresent()) {
      UserEntity user = userEntityRepository.findByUsername(verificationToken.get().getUserEmail());
      user.setEnabled(true);
      userDetailsManager.updateUser(userDetailsConverter.toDomain(user));
      tokenRepository.delete(verificationToken.get());
      return true;
    }
    return false;
  }
}
