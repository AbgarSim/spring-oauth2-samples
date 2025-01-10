import 'dart:async';
import 'dart:io' show Platform;
import 'package:app_links/app_links.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter_oauth2_jwt_client/auth/pkce_pair.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:oauth2/oauth2.dart' as oauth2;
import 'package:universal_html/html.dart' as html;

import 'package:flutter_oauth2_jwt_client/auth/auth_config.dart';

class AuthService {
  static final AuthService instance = AuthService._internal();

  AuthService._internal();

  static final AppLinks appLinks = AppLinks();

  static final _pkce = PkcePair.loadOrGenerate();

  oauth2.Client? _client;

  oauth2.AuthorizationCodeGrant? _grant;

  String? get accessToken => _client?.credentials.accessToken;

  Future<void> authorizationCodeGrantFlow() async {
    _grant = oauth2.AuthorizationCodeGrant(
        AuthConfig.clientId,
        Uri.parse(AuthConfig.authorizationEndpoint()),
        Uri.parse(AuthConfig.tokenEndpoint()),
        secret: AuthConfig.clientSecret,
        codeVerifier: _pkce.codeVerifier);

    final authorizationUrl = _grant!.getAuthorizationUrl(
      Uri.parse(AuthConfig.redirectUri()),
      scopes: ['read'],
    );

    if (kIsWeb) {
      html.window.location.assign(authorizationUrl.toString());
    } else {
      await launchUrl(authorizationUrl);

    }
  }

  Future<void> handleAuthorizationResponse({
    String? codeFromDeepLink,
  }) async {
    if (_grant == null) {
      _grant = oauth2.AuthorizationCodeGrant(
          AuthConfig.clientId,
          Uri.parse(AuthConfig.authorizationEndpoint()),
          Uri.parse(AuthConfig.tokenEndpoint()),
          secret: AuthConfig.clientSecret,
          codeVerifier: _pkce.codeVerifier);

      _grant!.getAuthorizationUrl(
        Uri.parse(AuthConfig.redirectUri()),
        scopes: ['read'],
      );
    }

    if (kIsWeb && (codeFromDeepLink == null || codeFromDeepLink.isEmpty)) {
      final codeStored = html.window.localStorage.remove('oauth_code');
      codeFromDeepLink = codeStored;
    }

    if (codeFromDeepLink == null || codeFromDeepLink.isEmpty) {
      throw 'No code found in callback';
    }

    try {
      _client = await _grant!.handleAuthorizationResponse({
        'code': codeFromDeepLink,
        'code_verifier': _pkce.codeChallenge,
      });

      print('Access Token: ${_client?.credentials.accessToken}');
    } catch (e, st) {
      print('Error finalizing code exchange: $e\n$st');
      rethrow;
    } finally {
      PkcePair.clearStoredPair();
    }
  }

  Future<String> fetchSomeProtectedResource() async {
    if (_client == null) {
      throw 'Not authenticated yet';
    }

    final response =
        await _client!.get(Uri.parse('https://api.example.com/data'));
    if (response.statusCode == 200) {
      return response.body;
    } else {
      throw 'Failed with status ${response.statusCode}: ${response.body}';
    }
  }
}
