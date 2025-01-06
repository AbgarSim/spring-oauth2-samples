class AuthConfig {
  static const String clientId = "sample-client";
  static const String clientSecret = "secret";
  static const String authorizationEndpoint = "http://127.0.0.1:9001/oauth2/authorize";
  static const String discoveryEndpoint = "http://127.0.0.1:9001/.well-known/openid-configuration";
  static const String issuer = "http://127.0.0.1:9001/";
  static const String tokenEndpoint = "http://127.0.0.1:9001/oauth2/token";
  static const String redirectUri = "http://localhost:8083/callback.html";
  static const List<String> scopes = ["openid", "read", "profile"];
  static const String resourceUrl = "http://127.0.0.1:8443/resource";
}