
DROP VIEW IF EXISTS overview_all;

CREATE VIEW overview_all AS
SELECT
a.unique_id,
a.timestamp,
source_ip.source_ip,
destination_port.destination_port,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.*,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN source_ip ON a.source_ip_id = source_ip.source_ip_id
LEFT OUTER JOIN destination_port ON a.destination_port_id = destination_port.destination_port_id
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.messages_id = messages.messages_id
WHERE
a.unique_id = b.unique_id AND a.unique_id =  h.unique_id AND a.unique_id = f.unique_id AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
ORDER BY uri;




DROP VIEW IF EXISTS falsepositive_all;

CREATE VIEW falsepositive_all AS
SELECT
a.unique_id,
a.timestamp,
destination_port.destination_port,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.*,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN destination_port ON a.destination_port_id = destination_port.destination_port_id
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id AND a.unique_id =  h.unique_id AND a.unique_id = f.unique_id AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
ORDER BY uri;





DROP VIEW IF EXISTS falsepositive_crs_20_protocol_violations;

CREATE VIEW falsepositive_crs_20_protocol_violations AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_20_protocol_violations,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_20_protocol_violations_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
--AND a.unique_id = main.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_20_protocol_violations > 0
ORDER BY uri;




DROP VIEW IF EXISTS falsepositive_crs_21_protocol_anomalies;

CREATE VIEW falsepositive_crs_21_protocol_anomalies AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_21_protocol_anomalies,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_21_protocol_anomalies_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
--AND a.unique_id = main.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_21_protocol_anomalies > 0
ORDER BY uri;




DROP VIEW IF EXISTS falsepositive_crs_23_request_limits;

CREATE VIEW falsepositive_crs_23_request_limits AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_23_request_limits,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_23_request_limits_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_23_request_limits > 0
ORDER BY uri;




DROP VIEW IF EXISTS falsepositive_crs_30_http_policy;

CREATE VIEW falsepositive_crs_30_http_policy AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_30_http_policy,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_30_http_policy_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_30_http_policy > 0
ORDER BY uri;




DROP VIEW IF EXISTS falsepositive_crs_35_bad_robots;

CREATE VIEW falsepositive_crs_35_bad_robots AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_35_bad_robots,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_35_bad_robots_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_35_bad_robots > 0
ORDER BY uri;





DROP VIEW IF EXISTS falsepositive_crs_40_generic_attacks;

CREATE VIEW falsepositive_crs_40_generic_attacks AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_40_generic_attacks,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_40_generic_attacks_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_40_generic_attacks > 0
ORDER BY uri;





DROP VIEW IF EXISTS falsepositive_crs_41_sql_injection_attacks;

CREATE VIEW falsepositive_crs_41_sql_injection_attacks AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_41_sql_injection_attacks,
messages.messages,
main.c
FROM a, b, f, h, anomaly_scores, main
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_41_sql_injection_attacks_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id AND a.unique_id =  h.unique_id AND a.unique_id = f.unique_id AND a.unique_id = anomaly_scores.unique_id AND a.unique_id = main.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_41_sql_injection_attacks > 0
ORDER BY uri;




DROP VIEW IF EXISTS falsepositive_crs_41_xss_attacks;

CREATE VIEW falsepositive_crs_41_xss_attacks AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_41_xss_attacks,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_41_xss_attacks_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_41_xss_attacks > 0
ORDER BY uri;





DROP VIEW IF EXISTS falsepositive_crs_42_tight_security;

CREATE VIEW falsepositive_crs_42_tight_security AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_42_tight_security,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_42_tight_security_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_42_tight_security > 0
ORDER BY uri;




--crs_45_trojans
DROP VIEW IF EXISTS falsepositive_crs_45_trojans;

CREATE VIEW falsepositive_crs_45_trojans AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_45_trojans,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_45_trojans_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_45_trojans > 0
ORDER BY uri;





-- crs_47_common_exceptions
DROP VIEW IF EXISTS falsepositive_crs_47_common_exceptions;

CREATE VIEW falsepositive_crs_47_common_exceptions AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_47_common_exceptions,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_47_common_exceptions_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_47_common_exceptions > 0
ORDER BY uri;





-- crs_48_local_exceptions
DROP VIEW IF EXISTS falsepositive_crs_48_local_exceptions;

CREATE VIEW falsepositive_crs_48_local_exceptions AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_48_local_exceptions,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_48_local_exceptions_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_48_local_exceptions > 0
ORDER BY uri;





-- crs_49_inbound_blocking
DROP VIEW IF EXISTS falsepositive_crs_49_inbound_blocking;

CREATE VIEW falsepositive_crs_49_inbound_blocking AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_49_inbound_blocking,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_49_inbound_blocking_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_49_inbound_blocking > 0
ORDER BY uri;





-- crs_50_outbound
DROP VIEW IF EXISTS falsepositive_crs_50_outbound;

CREATE VIEW falsepositive_crs_50_outbound AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_50_outbound,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.falsepositive_crs_50_outbound_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_50_outbound > 0
ORDER BY uri;





-- crs_59_outbound_blocking
DROP VIEW IF EXISTS falsepositive_crs_59_outbound_blocking;

CREATE VIEW falsepositive_crs_59_outbound_blocking AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_59_outbound_blocking,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_59_outbound_blocking_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_59_outbound_blocking > 0
ORDER BY uri;





-- crs_60_correlation
DROP VIEW IF EXISTS falsepositive_crs_60_correlation;

CREATE VIEW falsepositive_crs_60_correlation AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_60_correlation,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_60_correlation_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_60_correlation > 0
ORDER BY uri;




-- crs_11_brute_force
DROP VIEW IF EXISTS falsepositive_crs_11_brute_force;

CREATE VIEW falsepositive_crs_11_brute_force AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_11_brute_force,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_11_brute_force_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_11_brute_force > 0
ORDER BY uri;






-- crs_11_dos_protection
DROP VIEW IF EXISTS falsepositive_crs_11_dos_protection;

CREATE VIEW falsepositive_crs_11_dos_protection AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_11_dos_protection,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_11_dos_protection_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_11_dos_protection > 0
ORDER BY uri;






-- crs_11_slow_dos_protection
DROP VIEW IF EXISTS falsepositive_crs_11_slow_dos_protection;

CREATE VIEW falsepositive_crs_11_slow_dos_protection AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_11_slow_dos_protection,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_11_slow_dos_protection_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_11_slow_dos_protection > 0
ORDER BY uri;





-- crs_16_scanner_integration
DROP VIEW IF EXISTS falsepositive_crs_16_scanner_integration;

CREATE VIEW falsepositive_crs_16_scanner_integration AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_16_scanner_integration,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_16_scanner_integration_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_16_scanner_integration > 0
ORDER BY uri;







-- crs_25_cc_track_pan
DROP VIEW IF EXISTS falsepositive_crs_25_cc_track_pan;

CREATE VIEW falsepositive_crs_25_cc_track_pan AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_25_cc_track_pan,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_25_cc_track_pan_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_25_cc_track_pan > 0
ORDER BY uri;







-- crs_40_appsensor_detection_point
DROP VIEW IF EXISTS falsepositive_crs_40_appsensor_detection_point;

CREATE VIEW falsepositive_crs_40_appsensor_detection_point AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_40_appsensor_detection_point,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_40_appsensor_detection_point_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_40_appsensor_detection_point > 0
ORDER BY uri;







-- crs_40_http_parameter_pollution
DROP VIEW IF EXISTS falsepositive_crs_40_http_parameter_pollution;

CREATE VIEW falsepositive_crs_40_http_parameter_pollution AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_40_http_parameter_pollution,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_40_http_parameter_pollution_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_40_http_parameter_pollution > 0
ORDER BY uri;







-- crs_42_csp_enforcement
DROP VIEW IF EXISTS falsepositive_crs_42_csp_enforcement;

CREATE VIEW falsepositive_crs_42_csp_enforcement AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_42_csp_enforcement,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_42_csp_enforcement_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_42_csp_enforcement > 0
ORDER BY uri;






-- crs_46_scanner_integration
DROP VIEW IF EXISTS falsepositive_crs_46_scanner_integration;

CREATE VIEW falsepositive_crs_46_scanner_integration AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_45_trojans,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_46_scanner_integration_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_46_scanner_integration > 0
ORDER BY uri;



-- crs_48_bayes_analysis
DROP VIEW IF EXISTS falsepositive_crs_48_bayes_analysis;

CREATE VIEW falsepositive_crs_48_bayes_analysis AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_48_bayes_analysis,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_48_bayes_analysis_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_48_bayes_analysis > 0
ORDER BY uri;





-- crs_55_response_profiling
DROP VIEW IF EXISTS falsepositive_crs_55_response_profiling;

CREATE VIEW falsepositive_crs_55_response_profiling AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_55_response_profiling,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_55_response_profiling_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_55_response_profiling > 0
ORDER BY uri;





-- crs_56_pvi_checks
DROP VIEW IF EXISTS falsepositive_crs_56_pvi_checks;

CREATE VIEW falsepositive_crs_56_pvi_checks AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_56_pvi_checks,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_56_pvi_checks_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_56_pvi_checks > 0
ORDER BY uri;






-- crs_61_ip_forensics
DROP VIEW IF EXISTS falsepositive_crs_61_ip_forensics;

CREATE VIEW falsepositive_crs_61_ip_forensics AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_61_ip_forensics,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_61_ip_forensics_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_61_ip_forensics > 0
ORDER BY uri;



-- crs_10_ignore_static
DROP VIEW IF EXISTS falsepositive_crs_10_ignore_static;

CREATE VIEW falsepositive_crs_10_ignore_static AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_10_ignore_static,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_10_ignore_static_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_10_ignore_static > 0
ORDER BY uri;



-- crs_11_avs_traffic
DROP VIEW IF EXISTS falsepositive_crs_11_avs_traffic;

CREATE VIEW falsepositive_crs_11_avs_traffic AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_11_avs_traffic,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_11_avs_traffic_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_11_avs_traffic > 0
ORDER BY uri;




-- crs_13_xml_enabler
DROP VIEW IF EXISTS falsepositive_crs_13_xml_enabler;

CREATE VIEW falsepositive_crs_13_xml_enabler AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_13_xml_enabler,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_13_xml_enabler_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_13_xml_enabler > 0
ORDER BY uri;



-- crs_16_authentication_tracking
DROP VIEW IF EXISTS falsepositive_crs_16_authentication_tracking;

CREATE VIEW falsepositive_crs_16_authentication_tracking AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_16_authentication_tracking,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_16_authentication_tracking_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_16_authentication_tracking > 0
ORDER BY uri;



-- crs_16_session_hijacking
DROP VIEW IF EXISTS falsepositive_crs_16_session_hijacking;

CREATE VIEW falsepositive_crs_16_session_hijacking AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_16_session_hijacking,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_16_session_hijacking_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_16_session_hijacking > 0
ORDER BY uri;





-- crs_16_username_tracking
DROP VIEW IF EXISTS falsepositive_crs_16_username_tracking;

CREATE VIEW falsepositive_crs_16_username_tracking AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_16_username_tracking,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_16_username_tracking_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_16_username_tracking > 0
ORDER BY uri;



-- crs_25_cc_known
DROP VIEW IF EXISTS falsepositive_crs_25_cc_known;

CREATE VIEW falsepositive_crs_25_cc_known AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_25_cc_known,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_25_cc_known_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_25_cc_known > 0
ORDER BY uri;



-- crs_42_comment_spam
DROP VIEW IF EXISTS falsepositive_crs_42_comment_spam;

CREATE VIEW falsepositive_crs_42_comment_spam AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_42_comment_spam,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_42_comment_spam_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_42_comment_spam > 0
ORDER BY uri;



-- crs_43_csrf_protection
DROP VIEW IF EXISTS falsepositive_crs_43_csrf_protection;

CREATE VIEW falsepositive_crs_43_csrf_protection AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_43_csrf_protection,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_43_csrf_protection_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_43_csrf_protection > 0
ORDER BY uri;





-- crs_46_av_scanning
DROP VIEW IF EXISTS falsepositive_crs_46_av_scanning;

CREATE VIEW falsepositive_crs_46_av_scanning AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_46_av_scanning,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_46_av_scanning_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_46_av_scanning > 0
ORDER BY uri;





-- crs_47_skip_outbound_checks
DROP VIEW IF EXISTS falsepositive_crs_47_skip_outbound_checks;

CREATE VIEW falsepositive_crs_47_skip_outbound_checks AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_47_skip_outbound_checks,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_47_skip_outbound_checks_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_47_skip_outbound_checks > 0
ORDER BY uri;



-- crs_49_header_tagging
DROP VIEW IF EXISTS falsepositive_crs_49_header_tagging;

CREATE VIEW falsepositive_crs_49_header_tagging AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_49_header_tagging,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_49_header_tagging_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_49_header_tagging > 0
ORDER BY uri;






-- crs_55_application_defects
DROP VIEW IF EXISTS falsepositive_crs_55_application_defects;

CREATE VIEW falsepositive_crs_55_application_defects AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_55_application_defects,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_55_application_defects_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_55_application_defects > 0
ORDER BY uri;






-- crs_55_marketing
DROP VIEW IF EXISTS falsepositive_crs_55_marketing;

CREATE VIEW falsepositive_crs_55_marketing AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_55_marketing,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_55_marketing_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_55_marketing > 0
ORDER BY uri;






-- crs_59_header_tagging
DROP VIEW IF EXISTS falsepositive_crs_59_header_tagging;

CREATE VIEW falsepositive_crs_59_header_tagging AS
SELECT
a.unique_id,
a.timestamp,
request_method.request_method,
uri.uri,
http_status_text.http_status_text,
anomaly_scores.total_score,
anomaly_scores.crs_59_header_tagging,
messages.messages
FROM a, b, f, h, anomaly_scores
LEFT OUTER JOIN request_method ON b.request_method_id = request_method.request_method_id
LEFT OUTER JOIN uri ON b.uri_id = uri.uri_id
LEFT OUTER JOIN http_status_text ON f.http_status_text_id = http_status_text.http_status_text_id
LEFT OUTER JOIN messages ON h.crs_59_header_tagging_messages_id = messages.messages_id
WHERE
a.source_ip_id = (SELECT source_ip_id FROM source_ip WHERE source_ip = '192.168.1.1')
AND a.unique_id = b.unique_id
AND a.unique_id =  h.unique_id
AND a.unique_id = f.unique_id
AND a.unique_id = anomaly_scores.unique_id
AND anomaly_scores.total_score >=5
AND anomaly_scores.crs_59_header_tagging > 0
ORDER BY uri;


