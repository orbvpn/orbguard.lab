-- +goose Up
-- +goose StatementBegin

SET search_path TO orbguard_lab, public;

-- ============================================================================
-- SEED PEGASUS INDICATORS
-- Known Pegasus indicators from Citizen Lab, Amnesty Tech, Lookout, etc.
-- ============================================================================

-- Get campaign and source IDs
DO $$
DECLARE
    pegasus_campaign_id UUID;
    nso_actor_id UUID;
    pegasus_malware_id UUID;
    citizenlab_source_id UUID;
    amnesty_source_id UUID;
BEGIN
    SELECT id INTO pegasus_campaign_id FROM campaigns WHERE slug = 'pegasus';
    SELECT id INTO nso_actor_id FROM threat_actors WHERE name = 'NSO Group';
    SELECT id INTO pegasus_malware_id FROM malware_families WHERE name = 'Pegasus';
    SELECT id INTO citizenlab_source_id FROM sources WHERE slug = 'citizenlab';
    SELECT id INTO amnesty_source_id FROM sources WHERE slug = 'amnesty_mvt';

    -- Insert Pegasus domains
    INSERT INTO indicators (value, value_hash, type, severity, confidence, description, tags, platforms, campaign_id, threat_actor_id, malware_family_id, mitre_techniques, first_seen, last_seen)
    VALUES
    -- Known C2 domains
    ('lsgatag.com', encode(sha256('lsgatag.com'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Known Pegasus C2 domain', ARRAY['pegasus', 'nso-group', 'c2'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('lxwo.org', encode(sha256('lxwo.org'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Pegasus infrastructure', ARRAY['pegasus', 'nso-group'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('iosmac.org', encode(sha256('iosmac.org'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Pegasus iOS targeting', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('cloudatlasinc.com', encode(sha256('cloudatlasinc.com'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Pegasus front company', ARRAY['pegasus', 'nso-group'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('lighthouseresearch.com', encode(sha256('lighthouseresearch.com'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Pegasus infrastructure', ARRAY['pegasus'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('mynetsec.net', encode(sha256('mynetsec.net'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Pegasus C2', ARRAY['pegasus', 'c2'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('updates-icloud-content.com', encode(sha256('updates-icloud-content.com'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Fake iCloud domain', ARRAY['pegasus', 'ios', 'phishing'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071', 'T1566'], '2016-08-01', NOW()),
    ('backupios.com', encode(sha256('backupios.com'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Fake iOS backup', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('appcheck-store.net', encode(sha256('appcheck-store.net'::bytea), 'hex'), 'domain', 'critical', 0.95, 'Fake app store', ARRAY['pegasus'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2016-08-01', NOW()),
    ('recoverymail.info', encode(sha256('recoverymail.info'::bytea), 'hex'), 'domain', 'critical', 0.90, 'Pegasus phishing domain', ARRAY['pegasus', 'phishing'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1566'], '2019-01-01', NOW()),
    ('secureweb.tech', encode(sha256('secureweb.tech'::bytea), 'hex'), 'domain', 'critical', 0.90, 'Pegasus infrastructure', ARRAY['pegasus', 'nso-group'], ARRAY['android', 'ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1071'], '2019-01-01', NOW()),

    -- iOS process names
    ('setframed', encode(sha256('setframed'::bytea), 'hex'), 'process', 'critical', 0.95, 'Pegasus iOS process', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1424'], '2016-08-01', NOW()),
    ('bridged', encode(sha256('bridged'::bytea), 'hex'), 'process', 'critical', 0.95, 'Pegasus iOS process', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1424'], '2016-08-01', NOW()),
    ('CommsCentre', encode(sha256('CommsCentre'::bytea), 'hex'), 'process', 'critical', 0.95, 'Pegasus iOS process', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1424'], '2016-08-01', NOW()),
    ('aggregated', encode(sha256('aggregated'::bytea), 'hex'), 'process', 'high', 0.85, 'Suspicious iOS process', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1424'], '2016-08-01', NOW()),
    ('roleaboutd', encode(sha256('roleaboutd'::bytea), 'hex'), 'process', 'critical', 0.95, 'Pegasus iOS process', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1424'], '2019-01-01', NOW()),
    ('pcabordd', encode(sha256('pcabordd'::bytea), 'hex'), 'process', 'critical', 0.95, 'Pegasus iOS process', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1424'], '2019-01-01', NOW()),

    -- Android package names
    ('com.network.android', encode(sha256('com.network.android'::bytea), 'hex'), 'package', 'high', 0.85, 'Fake system package', ARRAY['android', 'spyware'], ARRAY['android']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1404'], '2016-08-01', NOW()),
    ('com.system.framework', encode(sha256('com.system.framework'::bytea), 'hex'), 'package', 'high', 0.85, 'Fake framework', ARRAY['android', 'spyware'], ARRAY['android']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1404'], '2016-08-01', NOW()),
    ('com.google.android.update', encode(sha256('com.google.android.update'::bytea), 'hex'), 'package', 'critical', 0.90, 'Fake Google update', ARRAY['android', 'spyware', 'pegasus'], ARRAY['android']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1404'], '2016-08-01', NOW()),
    ('com.android.battery', encode(sha256('com.android.battery'::bytea), 'hex'), 'package', 'medium', 0.70, 'Suspicious battery app', ARRAY['android'], ARRAY['android']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1404'], '2016-08-01', NOW()),
    ('com.android.systemadmin', encode(sha256('com.android.systemadmin'::bytea), 'hex'), 'package', 'high', 0.85, 'Fake system admin package', ARRAY['android', 'spyware', 'pegasus'], ARRAY['android']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1404'], '2019-01-01', NOW()),

    -- File paths (iOS)
    ('/private/var/tmp/.pegasus', encode(sha256('/private/var/tmp/.pegasus'::bytea), 'hex'), 'filepath', 'critical', 0.95, 'Pegasus temp file', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1420'], '2016-08-01', NOW()),
    ('/private/var/db/com.apple.xpc.roleaccountd.staging', encode(sha256('/private/var/db/com.apple.xpc.roleaccountd.staging'::bytea), 'hex'), 'filepath', 'critical', 0.95, 'Pegasus staging directory', ARRAY['pegasus', 'ios'], ARRAY['ios']::platform_type[], pegasus_campaign_id, nso_actor_id, pegasus_malware_id, ARRAY['T1420'], '2019-01-01', NOW())

    ON CONFLICT (value_hash) DO UPDATE SET
        last_seen = NOW(),
        updated_at = NOW();

    -- Link indicators to sources
    INSERT INTO indicator_sources (indicator_id, source_id, source_confidence, fetched_at)
    SELECT i.id, citizenlab_source_id, 0.95, NOW()
    FROM indicators i
    WHERE i.campaign_id = pegasus_campaign_id
    ON CONFLICT DO NOTHING;

    INSERT INTO indicator_sources (indicator_id, source_id, source_confidence, fetched_at)
    SELECT i.id, amnesty_source_id, 0.95, NOW()
    FROM indicators i
    WHERE i.campaign_id = pegasus_campaign_id
    ON CONFLICT DO NOTHING;

    -- Update source indicator counts
    UPDATE sources SET indicator_count = (
        SELECT COUNT(*) FROM indicator_sources WHERE source_id = sources.id
    );

    -- Update campaign indicator count
    UPDATE campaigns SET indicator_count = (
        SELECT COUNT(*) FROM indicators WHERE campaign_id = campaigns.id
    );

    -- Update threat actor indicator count
    UPDATE threat_actors SET indicator_count = (
        SELECT COUNT(*) FROM indicators WHERE threat_actor_id = threat_actors.id
    );

    -- Update malware family indicator count
    UPDATE malware_families SET indicator_count = (
        SELECT COUNT(*) FROM indicators WHERE malware_family_id = malware_families.id
    );

END $$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

SET search_path TO orbguard_lab, public;

-- Delete Pegasus indicators
DELETE FROM indicator_sources WHERE indicator_id IN (
    SELECT id FROM indicators WHERE campaign_id = (SELECT id FROM campaigns WHERE slug = 'pegasus')
);

DELETE FROM indicators WHERE campaign_id = (SELECT id FROM campaigns WHERE slug = 'pegasus');

-- Reset counts
UPDATE sources SET indicator_count = 0;
UPDATE campaigns SET indicator_count = 0;
UPDATE threat_actors SET indicator_count = 0;
UPDATE malware_families SET indicator_count = 0;

-- +goose StatementEnd
