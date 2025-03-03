package com.redpanda.springoauth2jwtauthorizationserver.security;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import java.io.IOException;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;

public class CustomUserPrincipalDeserializer extends JsonDeserializer<CustomUserDetails> {

  @Override
  public CustomUserDetails deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException {
    ObjectMapper mapper = (ObjectMapper) jsonParser.getCodec();
    JsonNode jsonNode = mapper.readTree(jsonParser);

    return CustomUserDetails.builder()
        .id(readJsonNode(jsonNode, "id").asText())
        .enabled(readJsonNode(jsonNode, "enable").asBoolean())
        .username(readJsonNode(jsonNode, "username").asText())
        .password(readJsonNode(jsonNode, "password").asText())
        .authorities(deserializeAuthorities(mapper, jsonNode))
        .build();
  }

  private JsonNode readJsonNode(JsonNode jsonNode, String field) {
    return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
  }

  public Set<GrantedAuthority> deserializeAuthorities(ObjectMapper mapper, JsonNode jsonNode) throws IOException {
    return mapper.readValue(jsonNode.get("authorities").toString(), new TypeReference<>() {
    });
  }

}
