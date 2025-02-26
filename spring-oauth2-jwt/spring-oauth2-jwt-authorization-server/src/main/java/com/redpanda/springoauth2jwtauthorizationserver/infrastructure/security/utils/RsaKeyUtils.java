package com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.utils;

import com.nimbusds.jose.jwk.RSAKey;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.RsaKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RsaKeyUtils {

  public static RsaKey generateNewRsaKeyPair(LocalDateTime keyCreationDate) {
    KeyPair keyPair = generateRsaKey();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAKey rsaKey = new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .keyID(UUID.randomUUID().toString())
        .build();

    LocalDateTime expiryDate = keyCreationDate.plusMonths(2); // Expire old key after 2 months

    RsaKey newRsaKey = new RsaKey();
    newRsaKey.setPublicKey(rsaKey.toPublicJWK().toJSONString());
    newRsaKey.setPrivateKey(rsaKey.toJSONString());
    newRsaKey.setKeyId(rsaKey.getKeyID());
    newRsaKey.setCreatedDate(keyCreationDate);
    newRsaKey.setExpiryDate(expiryDate);
    return newRsaKey;
  }

  private static KeyPair generateRsaKey() {
    KeyPair keyPair;
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      keyPair = keyPairGenerator.generateKeyPair();
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
    return keyPair;
  }

}
