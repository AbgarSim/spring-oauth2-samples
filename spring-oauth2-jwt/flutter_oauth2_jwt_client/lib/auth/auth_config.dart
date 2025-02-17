import 'package:flutter/foundation.dart';

class AuthConfig {
  static const String clientId = "sample-client";
  static const String clientSecret = "secret";

  static const String redirectUriWeb = "http://localhost:8083/callback.html";
  static const String redirectUriMobile = "com.sample.app://callback";
  static const List<String> scopes = ["openid", "read", "profile"];
  static const String resourceUrl = "http://127.0.0.1:8443/resource";

  static redirectUri() {
    if (kIsWeb) {
      return redirectUriWeb;
    } else {
      return redirectUriMobile;
    }
  }

  static String hostIp() {
    if(kIsWeb) {
      return "127.0.0.1";
    }else {
      return "10.0.2.2";
    }
  }

  static String issuer() {
    return "http://${hostIp()}:9001";
  }

  static String discoveryUrl() {
    return "http://${hostIp()}:9001/.well-known/openid-configuration";
  }

  static String authorizationEndpoint() {
    return "http://${hostIp()}:9001/oauth2/authorize";
  }

  static String tokenEndpoint() {
    return "http://${hostIp()}:9001/oauth2/token";
  }
}
