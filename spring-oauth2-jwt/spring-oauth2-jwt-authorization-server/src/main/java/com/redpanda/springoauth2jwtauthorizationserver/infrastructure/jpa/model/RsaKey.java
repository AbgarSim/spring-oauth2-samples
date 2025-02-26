package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;

@Data
@Entity
public class RsaKey {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  @Column(nullable = false, length = 5000)
  private String publicKey;

  @Column(nullable = false, length = 5000)
  private String privateKey;

  @Column(nullable = false, unique = true)
  private String keyId;

  @CreatedDate
  private LocalDateTime createdDate;

  @Column(nullable = false)
  private LocalDateTime expiryDate;
}

