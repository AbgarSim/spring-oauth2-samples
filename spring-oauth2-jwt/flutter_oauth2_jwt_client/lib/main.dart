import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:universal_html/html.dart' as html;

import 'auth/auth_client.dart';

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

  @override
  void initState() {
    super.initState();
    if (kIsWeb && html.window.localStorage.containsKey("oauth_code")) {
      final code = html.window.localStorage["oauth_code"];
      AuthClient.instance.processAuthResponse(code).then((_) {
        setState(() {
          _accessToken = AuthClient.instance.accessToken;
        });
      });
    }else if(!kIsWeb) {
      AppLinks().uriLinkStream.listen((Uri? uri) {
        if (uri != null && uri.scheme == "com.sample.app" && uri.host == "callback") {
          String? code = uri.queryParameters['code'];
          if (code != null) {
            AuthClient.instance.processAuthResponse(code).then((_) {
              setState(() {
                _accessToken = AuthClient.instance.accessToken;
              });
            });
          }
        }
      });
    }
  }

  Future<void> _login() async {
    await AuthClient.instance.login();
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
                    ElevatedButton(
                      child: Text('Fetch Protected Data'),
                      onPressed: () async {
                        try {
                          // Fetch protected resource
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
