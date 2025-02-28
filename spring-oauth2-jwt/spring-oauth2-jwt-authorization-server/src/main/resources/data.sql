INSERT INTO public.oauth2_client (id, authorization_grant_types, client_authentication_methods, client_id,
                                  client_id_issued_at, client_name, client_secret, client_secret_expires_at,
                                  client_settings, post_logout_redirect_uris, redirect_uris, scopes, token_settings)
VALUES ('c50b6fb2-3840-419b-a241-57e4b2aa7dcd', 'refresh_token,authorization_code', 'client_secret_basic',
        'sample-client', null, 'c50b6fb2-3840-419b-a241-57e4b2aa7dcd',
        '{bcrypt}$2a$10$lpIIuGtmjoofbwAwrB2y6.WP2RANOlD8oXmzFsUqmHMlLVjrS29Hm', null,
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true}',
        'http://localhost:8083/', 'http://localhost:8083/callback.html,com.sample.app://callback',
        'read,openid,profile',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.x509-certificate-bound-access-tokens":false,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000],"settings.token.authorization-code-time-to-live":["java.time.Duration",300.000000000],"settings.token.device-code-time-to-live":["java.time.Duration",300.000000000]}');
