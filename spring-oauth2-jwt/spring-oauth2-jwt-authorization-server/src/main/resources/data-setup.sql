-- Insert a test user
INSERT INTO users (id, username, password, enabled)
VALUES (9999999, 'user', '{noop}password', true);

-- Insert roles for the user
INSERT INTO user_entity_roles (user_entity_id, roles) VALUES (9999999, 'ROLE_USER');

-- Insert a registered OAuth2 client
INSERT INTO registered_client (id, client_id, client_secret)
VALUES ('123e4567-e89b-12d3-a456-426614174000', 'sample-client', '{noop}secret');

-- Insert client scopes
INSERT INTO registered_client_entity_scopes (registered_client_entity_id, scopes) VALUES
                                                                               ('123e4567-e89b-12d3-a456-426614174000', 'openid'),
                                                                               ('123e4567-e89b-12d3-a456-426614174000', 'profile'),
                                                                               ('123e4567-e89b-12d3-a456-426614174000', 'read');

-- Insert client redirect URIs
INSERT INTO registered_client_entity_redirect_uris (registered_client_entity_id, redirect_uris) VALUES
                                                                                             ('123e4567-e89b-12d3-a456-426614174000', 'http://localhost:8083/callback.html'),
                                                                                             ('123e4567-e89b-12d3-a456-426614174000', 'com.sample.app://callback');

-- Insert client grant types
INSERT INTO registered_client_entity_grant_types (registered_client_entity_id, grant_types) VALUES
                                                                                         ('123e4567-e89b-12d3-a456-426614174000', 'authorization_code'),
                                                                                         ('123e4567-e89b-12d3-a456-426614174000', 'refresh_token');

-- Insert client authentication methods
INSERT INTO registered_client_entity_authentication_methods (registered_client_entity_id, authentication_methods) VALUES
    ('123e4567-e89b-12d3-a456-426614174000', 'client_secret_basic');