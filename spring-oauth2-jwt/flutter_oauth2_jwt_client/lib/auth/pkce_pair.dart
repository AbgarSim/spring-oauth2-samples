import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart' show kIsWeb;

import 'package:universal_html/html.dart' as html;

/// A class representing a PKCE pair: [codeVerifier] and its matching [codeChallenge].
/// - [codeVerifier] is stored in memory on mobile/desktop.
/// - On web, it's saved to localStorage so we can retrieve it after a full page reload.
class PkcePair {
  /// The random string used by the client to derive [codeChallenge].
  final String codeVerifier;

  /// The base64URL-encoded hash of [codeVerifier].
  final String codeChallenge;

  /// Private constructor.
  PkcePair._(this.codeVerifier, this.codeChallenge);

  /// Loads an existing PKCE from localStorage (if on web and present).
  /// Otherwise generates a new one, and if on web, stores it in localStorage.
  static PkcePair loadOrGenerate() {
    if (kIsWeb) {
      // 1) Attempt to load from localStorage
      final storedVerifier = html.window.localStorage['pkce_code_verifier'];
      final storedChallenge = html.window.localStorage['pkce_code_challenge'];

      if (storedVerifier != null && storedChallenge != null) {
        // Found an existing PKCE, return it
        return PkcePair._(storedVerifier, storedChallenge);
      }
    }

    // 2) Nothing found on web or not running on web => Generate new
    final newVerifier = _generateRandomString(64);
    final hashBytes = sha256.convert(utf8.encode(newVerifier)).bytes;
    final newChallenge = _base64UrlEncodeNoPadding(hashBytes);

    // 3) If web, store them in localStorage so they survive a reload
    if (kIsWeb) {
      html.window.localStorage['pkce_code_verifier'] = newVerifier;
      html.window.localStorage['pkce_code_challenge'] = newChallenge;
    }

    return PkcePair._(newVerifier, newChallenge);
  }

  /// Optional: Clears any stored PKCE from localStorage on web.
  static void clearStoredPair() {
    if (kIsWeb) {
      html.window.localStorage.remove('pkce_code_verifier');
      html.window.localStorage.remove('pkce_code_challenge');
    }
  }

  /// Generates a random alphanumeric string of length [len].
  static String _generateRandomString(int len) {
    const chars =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    final rnd = Random.secure();
    return List.generate(len, (_) => chars[rnd.nextInt(chars.length)]).join();
  }

  /// Base64 URL-safe encode without padding
  static String _base64UrlEncodeNoPadding(List<int> bytes) {
    final base64String = base64Url.encode(bytes);
    return base64String.replaceAll('=', '');
  }
}
