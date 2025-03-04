package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "verification_tokens")
public class VerificationToken {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  private String token;
  private String userEmail;

  private LocalDateTime expiryDate;
}
