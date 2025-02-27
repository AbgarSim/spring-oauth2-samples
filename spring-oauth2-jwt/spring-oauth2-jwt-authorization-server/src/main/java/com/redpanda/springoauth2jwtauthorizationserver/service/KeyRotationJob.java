package com.redpanda.springoauth2jwtauthorizationserver.service;

import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.RsaKey;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.repository.RsaKeyRepository;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.utils.RsaKeyUtils;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class KeyRotationJob {

  private final RsaKeyRepository rsaKeyRepository;

  @Scheduled(cron = "0 0 0 1 * ?")
  public void rotateKeysJob() {

    LocalDateTime now = LocalDateTime.now();
    RsaKey rsaKey = RsaKeyUtils.generateNewRsaKeyPair(now);

    rsaKeyRepository.save(rsaKey);
    rsaKeyRepository.deleteExpiredKeys(now);
  }

}
