package com.redpanda.springoauth2jwtauthorizationserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.redpanda.springoauth2jwtauthorizationserver.security.CustomUserDetails;
import com.redpanda.springoauth2jwtauthorizationserver.security.CustomUserPrincipalMixin;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

@Configuration
public class ObjectMapperConfig {

  @Bean
  public ObjectMapper objectMapper() {
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.registerModule(new JavaTimeModule());
    objectMapper.registerModules(SecurityJackson2Modules.getModules(this.getClass().getClassLoader()));
    objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    objectMapper.addMixIn(CustomUserDetails.class, CustomUserPrincipalMixin.class);
    return objectMapper;
  }
}
