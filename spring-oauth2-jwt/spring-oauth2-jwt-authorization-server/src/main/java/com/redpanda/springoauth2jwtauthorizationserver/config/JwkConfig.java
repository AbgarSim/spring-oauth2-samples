package com.redpanda.springoauth2jwtauthorizationserver.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.model.RsaKey;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.jpa.repository.RsaKeyRepository;
import com.redpanda.springoauth2jwtauthorizationserver.infrastructure.security.utils.RsaKeyUtils;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Slf4j
//@Configuration
@RequiredArgsConstructor
public class JwkConfig {

  private final RsaKeyRepository rsaKeyRepository;

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    List<RsaKey> rsaKeys = rsaKeyRepository.findAll();
    List<JWK> jwks = rsaKeys.stream().map(rsaKey -> {
      try {
        RSAPublicKey publicKey = (RSAPublicKey) RSAKey.parse(rsaKey.getPublicKey()).toPublicKey();
        RSAPrivateKey privateKey = (RSAPrivateKey) RSAKey.parse(rsaKey.getPrivateKey()).toPrivateKey();
        return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(rsaKey.getKeyId())
            .build();
      } catch (ParseException | JOSEException e) {
        log.error("RSA Key parse exception: " + e.getMessage());
        throw new IllegalStateException("RSA Key parse exception!", e);
      }
    }).collect(Collectors.toList());

    if (jwks.isEmpty()) {
      RsaKey rsaKey = RsaKeyUtils.generateNewRsaKeyPair(LocalDateTime.now());
      rsaKeyRepository.save(rsaKey);

      try {
        RSAPublicKey publicKey = (RSAPublicKey) RSAKey.parse(rsaKey.getPublicKey()).toPublicKey();
        RSAPrivateKey privateKey = (RSAPrivateKey) RSAKey.parse(rsaKey.getPrivateKey()).toPrivateKey();
        jwks.add(new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(rsaKey.getKeyId())
            .build()
        );
      } catch (ParseException | JOSEException e) {
        log.error("RSA Key parse exception: " + e.getMessage());
        throw new IllegalStateException("RSA Key parse exception!", e);
      }
    }
    JWKSet jwkSet = new JWKSet(jwks);
    return new ImmutableJWKSet<>(jwkSet);
  }
}
