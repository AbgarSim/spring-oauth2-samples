import 'dart:async';
import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:universal_html/html.dart' as html;
import 'package:url_launcher/url_launcher.dart';

import 'auth_config.dart';
import 'pkce_pair.dart';

abstract class OAuthStrategy {
  Future<void> authenticate();

  Future<String?> handleAuthorizationResponse(String? code);
}

class WebOAuthStrategy implements OAuthStrategy {
  final Dio _dio;
  final PkcePair _pkce;

  WebOAuthStrategy(this._dio, this._pkce);

  @override
  Future<void> authenticate() async {
    final authorizationUrl =
        Uri.parse(AuthConfig.authorizationEndpoint()).replace(
      queryParameters: {
        'client_id': AuthConfig.clientId,
        'redirect_uri': AuthConfig.redirectUri(),
        'response_type': 'code',
        'code_challenge': _pkce.codeChallenge,
        'code_challenge_method': 'S256',
        'scope': 'read',
      },
    );

    html.window.location.assign(authorizationUrl.toString());
  }

  @override
  Future<String?> handleAuthorizationResponse(String? code) async {
    if (code == null) {
      code = html.window.localStorage.remove('oauth_code');
    }

    if (code == null || code.isEmpty) {
      throw Exception('No authorization code found');
    }

    final response = await _dio.post(
      AuthConfig.tokenEndpoint(),
      options: Options(
        headers: {
          'Authorization': 'Basic ' +
              base64Encode(utf8
                  .encode('${AuthConfig.clientId}:${AuthConfig.clientSecret}')),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
      ),
      data: {
        'client_id': AuthConfig.clientId,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': AuthConfig.redirectUri(),
        'code_verifier': _pkce.codeVerifier,
      },
    );

    return response.data['access_token'];
  }
}

class MobileOAuthStrategy implements OAuthStrategy {
  final Dio _dio;
  final PkcePair _pkce;

  MobileOAuthStrategy(this._dio, this._pkce);

  @override
  Future<void> authenticate() async {
    final authorizationUrl =
        Uri.parse(AuthConfig.authorizationEndpoint()).replace(
      queryParameters: {
        'client_id': AuthConfig.clientId,
        'client_secret': AuthConfig.clientSecret,
        'redirect_uri': AuthConfig.redirectUri(),
        'response_type': 'code',
        'code_challenge': _pkce.codeChallenge,
        'code_challenge_method': 'S256',
        'scope': 'read',
      },
    );

    await launchUrl(authorizationUrl, mode: LaunchMode.externalApplication);
  }

  @override
  Future<String?> handleAuthorizationResponse(String? code) async {
    if (code == null) {
      throw Exception('No authorization code found');
    }

    final response = await _dio.post(
      AuthConfig.tokenEndpoint(),
      options: Options(
        headers: {
          'Authorization': 'Basic ' +
              base64Encode(utf8
                  .encode('${AuthConfig.clientId}:${AuthConfig.clientSecret}')),
          'Content-Type': 'application/x-www-form-urlencoded'
        },
      ),
      data: {
        'client_id': AuthConfig.clientId,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': AuthConfig.redirectUri(),
        'code_verifier': _pkce.codeVerifier,
      },
    );

    return response.data['access_token'];
  }
}

class AuthClient {
  static final AuthClient instance = AuthClient._internal();
  late OAuthStrategy _strategy;
  final PkcePair _pkce = PkcePair.loadOrGenerate();
  final Dio _dio = Dio();
  String? _accessToken;

  AuthClient._internal() {
    _strategy = kIsWeb
        ? WebOAuthStrategy(_dio, _pkce)
        : MobileOAuthStrategy(_dio, _pkce);
  }

  String? get accessToken => _accessToken;

  Future<void> login() async {
    await _strategy.authenticate();
  }

  Future<void> processAuthResponse(String? code) async {
    _accessToken = await _strategy.handleAuthorizationResponse(code);
  }
}
