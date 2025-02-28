package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.repository;


import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.model.RsaKey;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface RsaKeyRepository extends JpaRepository<RsaKey, Long> {
  @Modifying
  @Query("DELETE FROM RsaKey rk WHERE rk.expiryDate < :now")
  void deleteExpiredKeys(LocalDateTime now);

  List<RsaKey> findByKeyId(String keyId);
}


