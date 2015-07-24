PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

-- main tables corresponding to sections in the audit log
-- required values have NOT NULL (since they must map to something), values where there may be no match are DEFAULT NULL
CREATE TABLE main                                   (UNIQUE_ID TEXT PRIMARY KEY,    HEADER TEXT,    A TEXT, B TEXT, C TEXT, D TEXT, E TEXT, F TEXT, G TEXT, H TEXT, I TEXT, J TEXT, K TEXT);
CREATE TABLE a                                      (unique_id TEXT PRIMARY KEY,    timestamp TEXT, unixtime TEXT, source_ip_id INTEGER NOT NULL, source_port_id INTEGER NOT NULL, destination_ip_id INTEGER NOT NULL, destination_port_id INTEGER NOT NULL);
CREATE TABLE b                                      (unique_id TEXT PRIMARY KEY,    request_method_id INTEGER NOT NULL, uri_id INTEGER NOT NULL,  http_version_id INTEGER DEFAULT NULL, host_id INTEGER DEFAULT NULL, connection_id INTEGER DEFAULT NULL, accept_id INTEGER DEFAULT NULL, user_agent_id INTEGER DEFAULT NULL, dnt_id INTEGER DEFAULT NULL, referrer_id INTEGER DEFAULT NULL, accept_encoding_id INTEGER DEFAULT NULL, accept_language_id INTEGER DEFAULT NULL, cookie_id INTEGER DEFAULT NULL,x_requested_with_id INTEGER DEFAULT NULL, content_type_id INTEGER DEFAULT NULL, content_length_id INTEGER DEFAULT NULL, proxy_connection_id INTEGER DEFAULT NULL, accept_charset_id INTEGER DEFAULT NULL, ua_cpu_id INTEGER DEFAULT NULL, x_forwarded_for_id INTEGER DEFAULT NULL, cache_control_id INTEGER DEFAULT NULL, via_id INTEGER DEFAULT NULL, if_modified_since_id INTEGER DEFAULT NULL, if_none_match_id INTEGER DEFAULT NULL, pragma_id INTEGER DEFAULT NULL);
CREATE TABLE f                                      (unique_id TEXT PRIMARY KEY,    http_version_id INTEGER DEFAULT NULL,  http_status_code_id INTEGER DEFAULT NULL, http_status_text_id INTEGER DEFAULT NULL, x_powered_by_id INTEGER DEFAULT NULL, expires_id INTEGER DEFAULT NULL, cache_control_id INTEGER DEFAULT NULL, pragma_id INTEGER DEFAULT NULL, vary_id INTEGER DEFAULT NULL, content_encoding_id INTEGER DEFAULT NULL, content_length_id INTEGER DEFAULT NULL, connection_id INTEGER DEFAULT NULL, content_type_id INTEGER DEFAULT NULL, status_id INTEGER DEFAULT NULL, keep_alive_id INTEGER DEFAULT NULL);
CREATE TABLE h                                      (unique_id TEXT PRIMARY KEY,    messages_id INTEGER DEFAULT NULL,  apache_handler_id INTEGER DEFAULT NULL, 	stopwatch TEXT, stopwatch2 TEXT, producer_id INTEGER DEFAULT NULL, server_id INTEGER DEFAULT NULL, engine_mode_id INTEGER DEFAULT NULL, action_id INTEGER DEFAULT NULL, apache_error_id INTEGER DEFAULT NULL, xml_parser_error_id INTEGER DEFAULT NULL);

-- parameter tables
-- A
-- timestamp
CREATE TABLE source_ip                              (source_ip_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, source_ip TEXT UNIQUE NOT NULL);
CREATE TABLE source_port                            (source_port_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, source_port TEXT UNIQUE NOT NULL);
CREATE TABLE destination_ip                         (destination_ip_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, destination_ip TEXT UNIQUE NOT NULL);
CREATE TABLE destination_port                       (destination_port_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, destination_port TEXT UNIQUE NOT NULL);

-- B
CREATE TABLE request_method                         (request_method_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, request_method TEXT UNIQUE NOT NULL);
CREATE TABLE uri                                    (uri_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, uri TEXT UNIQUE NOT NULL);
CREATE TABLE http_version_b                         (http_version_b_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, http_version_b TEXT UNIQUE NOT NULL);
CREATE TABLE hosts                                  (host_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, host TEXT UNIQUE NOT NULL);
CREATE TABLE connection_b                           (connection_b_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, connection_b TEXT UNIQUE NOT NULL);
CREATE TABLE accept                                 (accept_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, accept TEXT UNIQUE NOT NULL);
CREATE TABLE user_agent                             (user_agent_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, user_agent TEXT UNIQUE NOT NULL);
CREATE TABLE dnt                                    (dnt_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, dnt TEXT UNIQUE NOT NULL);
CREATE TABLE referrer                               (referrer_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, referrer TEXT UNIQUE NOT NULL);
CREATE TABLE accept_encoding                        (accept_encoding_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, accept_encoding TEXT UNIQUE NOT NULL);
CREATE TABLE accept_language                        (accept_language_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, accept_language TEXT UNIQUE NOT NULL);
CREATE TABLE cookie                                 (cookie_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, cookie TEXT UNIQUE NOT NULL);
CREATE TABLE x_requested_with                       (x_requested_with_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, x_requested_with TEXT UNIQUE NOT NULL);
CREATE TABLE content_type_b                         (content_type_b_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, content_type_b TEXT UNIQUE NOT NULL);
CREATE TABLE content_length_b                       (content_length_b_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, content_length_b TEXT UNIQUE NOT NULL);
CREATE TABLE proxy_connection                       (proxy_connection_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, proxy_connection TEXT UNIQUE NOT NULL);
CREATE TABLE accept_charset                         (accept_charset_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, accept_charset TEXT UNIQUE NOT NULL);
CREATE TABLE ua_cpu                                 (ua_cpu_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, ua_cpu TEXT UNIQUE NOT NULL);
CREATE TABLE x_forwarded_for                        (x_forwarded_for_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, x_forwarded_for TEXT UNIQUE NOT NULL);
CREATE TABLE cache_control_b                        (cache_control_b_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, cache_control_b TEXT UNIQUE NOT NULL);
CREATE TABLE via                                    (via_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, via TEXT UNIQUE NOT NULL);
CREATE TABLE if_modified_since                      (if_modified_since_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, if_modified_since TEXT UNIQUE NOT NULL);
CREATE TABLE if_none_match                          (if_none_match_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, if_none_match TEXT UNIQUE NOT NULL);
CREATE TABLE pragma_b                               (pragma_b_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, pragma_b TEXT UNIQUE NOT NULL);

-- F
CREATE TABLE http_version_f                         (http_version_f_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, http_version_f TEXT UNIQUE NOT NULL);
CREATE TABLE http_status_code                       (http_status_code_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, http_status_code TEXT UNIQUE NOT NULL);
CREATE TABLE http_status_text                       (http_status_text_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, http_status_text TEXT UNIQUE NOT NULL);
CREATE TABLE x_powered_by                           (x_powered_by_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, x_powered_by TEXT UNIQUE NOT NULL);
CREATE TABLE expires                                (expires_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, expires TEXT UNIQUE NOT NULL);
CREATE TABLE cache_control_f                        (cache_control_f_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, cache_control_f TEXT UNIQUE NOT NULL);
CREATE TABLE pragma_f                               (pragma_f_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, pragma_f TEXT UNIQUE NOT NULL);
CREATE TABLE vary                                   (vary_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, vary TEXT UNIQUE NOT NULL);
CREATE TABLE content_encoding                       (content_encoding_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, content_encoding TEXT UNIQUE NOT NULL);
CREATE TABLE content_length_f                       (content_length_f_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, content_length_f TEXT UNIQUE NOT NULL);
CREATE TABLE connection_f                           (connection_f_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, connection_f TEXT UNIQUE NOT NULL);
CREATE TABLE content_type_f                         (content_type_f_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, content_type_f TEXT UNIQUE NOT NULL);
CREATE TABLE status                                 (status_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, status TEXT UNIQUE NOT NULL);
CREATE TABLE keep_alive                             (keep_alive_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, keep_alive TEXT UNIQUE NOT NULL);


-- H
CREATE TABLE messages                               (messages_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, messages TEXT UNIQUE NOT NULL);
CREATE TABLE apache_handler                         (apache_handler_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, apache_handler TEXT UNIQUE NOT NULL);
-- stopwatch
-- stopwatch2
CREATE TABLE producer                               (producer_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, producer TEXT UNIQUE NOT NULL);
CREATE TABLE server                                 (server_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, server TEXT UNIQUE NOT NULL);
CREATE TABLE engine_mode                            (engine_mode_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, engine_mode TEXT UNIQUE NOT NULL);
CREATE TABLE action                                 (action_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, action TEXT UNIQUE NOT NULL);
CREATE TABLE apache_error                           (apache_error_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, apache_error TEXT UNIQUE NOT NULL);
CREATE TABLE xml_parser_error                       (xml_parser_error_id INTEGER DEFAULT 0 NOT NULL PRIMARY KEY, xml_parser_error TEXT UNIQUE NOT NULL);


COMMIT;
