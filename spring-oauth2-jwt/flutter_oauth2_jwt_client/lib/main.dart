import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:universal_html/html.dart' as html;

import 'package:flutter_oauth2_jwt_client/auth/auth_service.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String? _accessToken;
  final _authService = AuthService.instance;

  @override
  void initState() {
    super.initState();

    if (kIsWeb) {
      if (html.window.localStorage.containsKey("oauth_code")) {
        _authService.handleAuthorizationResponse().then((_) {
          setState(() {
            _accessToken = _authService.accessToken;
          });
        }).catchError((err) {
          print('Error during web callback handle: $err');
        });
      }
    }
  }

  Future<void> _login() async {
    await _authService.authorizationCodeGrantFlow();

  }



  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OAuth2 Demo',
      home: Scaffold(
        appBar: AppBar(title: Text('OAuth2 Authorization Code Flow')),
        body: Center(
          child: _accessToken == null
              ? ElevatedButton(
                  child: Text('Sign In'),
                  onPressed: _login,
                )
              : Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text('Access Token: $_accessToken'),
// e.g. Button to call a protected resource
                    ElevatedButton(
                      child: Text('Fetch Protected Data'),
                      onPressed: () async {
                        try {
                          final data =
                              await _authService.fetchSomeProtectedResource();
                          print(data);
                        } catch (e) {
                          print('Error fetching resource: $e');
                        }
                      },
                    ),
                  ],
                ),
        ),
      ),
    );
  }
}
