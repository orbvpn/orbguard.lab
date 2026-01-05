-- +goose Up
-- +goose StatementBegin

SET search_path TO orbguard_lab, public;

-- ============================================================================
-- SEED SOURCES
-- ============================================================================

INSERT INTO sources (name, slug, description, category, type, status, api_url, feed_url, github_urls, requires_api_key, reliability, weight, update_interval) VALUES
-- Abuse.ch Suite
('URLhaus', 'urlhaus', 'Abuse.ch URLhaus - Malware URL Database', 'abuse_ch', 'api', 'active', 'https://urlhaus-api.abuse.ch/v1', NULL, NULL, FALSE, 0.80, 1.00, '15 minutes'),
('ThreatFox', 'threatfox', 'Abuse.ch ThreatFox - IOC Sharing Platform', 'abuse_ch', 'api', 'active', 'https://threatfox-api.abuse.ch/api/v1', NULL, NULL, FALSE, 0.85, 1.00, '15 minutes'),
('MalwareBazaar', 'malwarebazaar', 'Abuse.ch MalwareBazaar - Malware Samples', 'abuse_ch', 'api', 'active', 'https://mb-api.abuse.ch/api/v1', NULL, NULL, FALSE, 0.85, 1.00, '4 hours'),
('Feodo Tracker', 'feodotracker', 'Abuse.ch Feodo Tracker - Botnet C2 Tracker', 'abuse_ch', 'feed', 'active', NULL, 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv', NULL, FALSE, 0.85, 1.00, '1 hour'),
('SSL Blacklist', 'sslblacklist', 'Abuse.ch SSL Blacklist - Malicious SSL Certificates', 'abuse_ch', 'feed', 'active', NULL, 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv', NULL, FALSE, 0.80, 1.00, '24 hours'),

-- Phishing
('OpenPhish', 'openphish', 'OpenPhish - Phishing Intelligence', 'phishing', 'feed', 'active', NULL, 'https://openphish.com/feed.txt', NULL, FALSE, 0.75, 0.80, '4 hours'),
('PhishTank', 'phishtank', 'PhishTank - Community Phishing Data', 'phishing', 'api', 'paused', NULL, NULL, NULL, TRUE, 0.70, 0.80, '4 hours'),

-- Mobile/Spyware (HIGH PRIORITY)
('Citizen Lab', 'citizenlab', 'Citizen Lab Malware Indicators', 'mobile', 'github', 'active', NULL, NULL, ARRAY['https://raw.githubusercontent.com/citizenlab/malware-indicators/master/'], FALSE, 0.95, 1.50, '6 hours'),
('Amnesty MVT', 'amnesty_mvt', 'Amnesty International Mobile Verification Toolkit', 'mobile', 'github', 'active', NULL, NULL, ARRAY['https://raw.githubusercontent.com/AmnestyTech/investigations/master/'], FALSE, 0.95, 1.50, '6 hours'),
('Koodous', 'koodous', 'Koodous Android Malware Analysis', 'mobile', 'api', 'paused', NULL, NULL, NULL, TRUE, 0.80, 1.20, '6 hours'),

-- General
('AlienVault OTX', 'alienvault_otx', 'AlienVault Open Threat Exchange', 'general', 'api', 'paused', NULL, NULL, NULL, TRUE, 0.75, 1.00, '4 hours'),
('VirusTotal', 'virustotal', 'VirusTotal Threat Intelligence', 'general', 'api', 'paused', NULL, NULL, NULL, TRUE, 0.90, 1.20, '1 hour'),

-- Community
('Community Reports', 'community', 'User-submitted threat reports', 'community', 'community', 'active', NULL, NULL, NULL, FALSE, 0.50, 0.50, '0 seconds');

-- ============================================================================
-- SEED THREAT ACTORS
-- ============================================================================

INSERT INTO threat_actors (name, aliases, description, type, motivation, country, active, target_sectors, target_regions, common_techniques, "references") VALUES
('NSO Group', ARRAY['Q Cyber Technologies'], 'Israeli cyber intelligence company known for Pegasus spyware', 'private-sector', 'surveillance', 'Israel', TRUE, ARRAY['journalism', 'activists', 'government', 'lawyers'], NULL, ARRAY['T1430', 'T1417', 'T1636.004', 'T1512', 'T1429'], ARRAY['https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/']),
('Cytrox', ARRAY['Intellexa'], 'Spyware vendor known for Predator', 'private-sector', 'surveillance', 'North Macedonia', TRUE, ARRAY['journalism', 'politicians', 'activists'], NULL, NULL, NULL),
('RCS Lab', NULL, 'Italian spyware company', 'private-sector', 'surveillance', 'Italy', TRUE, ARRAY['activists', 'government'], NULL, NULL, NULL),
('FinFisher', ARRAY['Gamma Group'], 'Surveillance software company (shut down)', 'private-sector', 'surveillance', 'Germany', FALSE, NULL, NULL, NULL, NULL);

-- ============================================================================
-- SEED MALWARE FAMILIES
-- ============================================================================

INSERT INTO malware_families (name, description, type, platforms, techniques, capabilities, first_seen, last_seen, "references") VALUES
('Pegasus', 'Advanced mobile spyware by NSO Group', 'spyware', ARRAY['android', 'ios']::platform_type[], ARRAY['T1430', 'T1417', 'T1636.004', 'T1512', 'T1429'], ARRAY['keylogging', 'screen_capture', 'microphone_access', 'camera_access', 'location_tracking', 'message_interception', 'contact_exfiltration'], '2016-08-01', NOW(), ARRAY['https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/', 'https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/']),
('Predator', 'Mobile spyware by Cytrox/Intellexa', 'spyware', ARRAY['android', 'ios']::platform_type[], NULL, NULL, '2019-01-01', NOW(), NULL),
('Hermit', 'Mobile spyware by RCS Lab', 'spyware', ARRAY['android', 'ios']::platform_type[], NULL, NULL, '2019-01-01', NOW(), NULL);

-- ============================================================================
-- SEED CAMPAIGNS
-- ============================================================================

INSERT INTO campaigns (name, slug, description, status, threat_actor_id, target_sectors, target_platforms, mitre_techniques, first_seen, last_seen, "references") VALUES
('Pegasus', 'pegasus', 'NSO Group''s Pegasus spyware targeting iOS and Android devices', 'active', (SELECT id FROM threat_actors WHERE name = 'NSO Group'), ARRAY['journalism', 'activists', 'government', 'lawyers'], ARRAY['ios', 'android']::platform_type[], ARRAY['T1430', 'T1417', 'T1636.004', 'T1512', 'T1429'], '2016-08-01', NOW(), ARRAY['https://citizenlab.ca/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/', 'https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/']),
('Predator', 'predator', 'Cytrox''s Predator spyware similar to Pegasus', 'active', (SELECT id FROM threat_actors WHERE name = 'Cytrox'), ARRAY['journalism', 'politicians', 'activists'], ARRAY['ios', 'android']::platform_type[], NULL, '2019-01-01', NOW(), NULL),
('Hermit', 'hermit', 'Italian spyware by RCS Lab targeting Android and iOS', 'active', (SELECT id FROM threat_actors WHERE name = 'RCS Lab'), ARRAY['activists', 'government'], ARRAY['ios', 'android']::platform_type[], NULL, '2019-01-01', NOW(), NULL);

-- Link malware families to campaigns
UPDATE malware_families SET threat_actor_id = (SELECT id FROM threat_actors WHERE name = 'NSO Group') WHERE name = 'Pegasus';
UPDATE malware_families SET threat_actor_id = (SELECT id FROM threat_actors WHERE name = 'Cytrox') WHERE name = 'Predator';
UPDATE malware_families SET threat_actor_id = (SELECT id FROM threat_actors WHERE name = 'RCS Lab') WHERE name = 'Hermit';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

SET search_path TO orbguard_lab, public;

DELETE FROM campaigns;
DELETE FROM malware_families;
DELETE FROM threat_actors;
DELETE FROM sources;

-- +goose StatementEnd
