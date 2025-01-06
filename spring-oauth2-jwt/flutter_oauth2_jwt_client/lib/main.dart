import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'dart:html' as html;
import 'package:flutter_oauth2_jwt_client/auth/auth_config.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Demo App',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      // This onGenerateRoute simply checks if "callback" is in the URL and
      // extracts the 'code' substring. Then it builds the OAuthExample page
      // passing the code as a constructor argument.
      onGenerateRoute: (RouteSettings routeSettings) {
        String code = "";

        // Example check: if the route name contains "callback",
        // parse out the code. This is a quick hack to show how
        // you might detect the presence of a code in the URL.
        if (routeSettings.name != null && routeSettings.name!.contains("callback")) {
          final fullUri = Uri.base.toString();
          final indexOfCode = fullUri.indexOf('code=');
          if (indexOfCode != -1) {
            // Extract everything after 'code='
            code = fullUri.substring(indexOfCode + 5);
            // If there's an ampersand after the code, remove everything after it.
            final ampIndex = code.indexOf('&');
            if (ampIndex != -1) {
              code = code.substring(0, ampIndex);
            }
          }
        }

        return MaterialPageRoute(
          builder: (BuildContext context) {
            return OAuthExample(code: code);
          },
        );
      },
    );
  }
}

class OAuthExample extends StatefulWidget {
  final String? code;

  const OAuthExample({
    Key? key,
    this.code,
  }) : super(key: key);

  @override
  _OAuthExampleState createState() => _OAuthExampleState();
}

class _OAuthExampleState extends State<OAuthExample> {
  final Dio dio = Dio();
  String? accessToken;

  @override
  void initState() {
    super.initState();
    // If a code is present, automatically exchange it for a token.
    if (widget.code != null && widget.code!.isNotEmpty) {
      processAuthorizationCode(widget.code!);
    }
  }

  /// Build the authorization URL manually:
  /// e.g. https://<auth-server>/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=read
  String _buildAuthorizationUrl() {
    final params = {
      'response_type': 'code',
      'client_id': AuthConfig.clientId,
      'redirect_uri': AuthConfig.redirectUri,
      'scope': 'read', // Adjust scopes if needed
    };

    // Construct the query string
    final queryString = Uri(queryParameters: params).query;
    // Append to AuthConfig.authorizationEndpoint
    return '${AuthConfig.authorizationEndpoint}?$queryString';
  }

  /// Step 1: Redirect user to the authorization endpoint to sign in.
  Future<void> login() async {
    final authorizationUrl = _buildAuthorizationUrl();

    // Full page redirect to the authorization server
    html.window.location.assign(authorizationUrl);
  }

  /// Step 2: Exchange the authorization code for an access token using Dio.
  Future<void> processAuthorizationCode(String code) async {
    print(code);
    try {
      final response = await dio.post(
        AuthConfig.tokenEndpoint,
        data: {
          'grant_type': 'authorization_code',
          'client_id': AuthConfig.clientId,
          'client_secret': AuthConfig.clientSecret,
          'redirect_uri': AuthConfig.redirectUri,
          'code': code,
        },
        options: Options(
          // Typically OAuth2 endpoints expect form-encoded data
          contentType: Headers.formUrlEncodedContentType,
        ),
      );

      if (response.statusCode == 200) {
        final data = response.data;
        // The exact fields depend on your OAuth server's response format
        final token = data['access_token'] as String?;
        setState(() {
          accessToken = token;
        });
        print('Access Token: $accessToken');
      } else {
        print('Token endpoint returned status ${response.statusCode}');
      }
    } catch (e) {
      print('Error exchanging code for token: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text("OAuth2 Authorization Code (Dio)"),
      ),
      body: Center(
        child: accessToken == null
            ? ElevatedButton(
          onPressed: login,
          child: Text("Login"),
        )
            : Text("Logged in!\nAccess Token: $accessToken"),
      ),
    );
  }
}