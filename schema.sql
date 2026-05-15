-- snickr schema (CS6083 Project 2)
-- Drop in reverse dependency order
DROP TABLE IF EXISTS message_attachments CASCADE;
DROP TABLE IF EXISTS message_reactions CASCADE;
DROP TABLE IF EXISTS pinned_messages CASCADE;
DROP TABLE IF EXISTS channel_last_read CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS channel_invitations CASCADE;
DROP TABLE IF EXISTS channel_members CASCADE;
DROP TABLE IF EXISTS channels CASCADE;
DROP TABLE IF EXISTS workspace_invitations CASCADE;
DROP TABLE IF EXISTS workspace_members CASCADE;
DROP TABLE IF EXISTS workspaces CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ─────────────────────────────────────────
-- Core tables
-- ─────────────────────────────────────────

CREATE TABLE users (
    user_id       SERIAL PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL UNIQUE,
    nickname      VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE workspaces (
    workspace_id SERIAL PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    description  TEXT,
    created_by   INTEGER      NOT NULL REFERENCES users(user_id),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE workspace_members (
    workspace_id INTEGER     NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    user_id      INTEGER     NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    is_admin     BOOLEAN     NOT NULL DEFAULT FALSE,
    joined_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (workspace_id, user_id)
);

-- Workspace invitations: admins invite users; users accept/decline
CREATE TABLE workspace_invitations (
    invitation_id   SERIAL PRIMARY KEY,
    workspace_id    INTEGER     NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    invited_by      INTEGER     NOT NULL REFERENCES users(user_id),
    invited_user_id INTEGER     NOT NULL REFERENCES users(user_id),
    status          VARCHAR(10) NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending','accepted','declined')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, invited_user_id)
);

CREATE TABLE channels (
    channel_id   SERIAL PRIMARY KEY,
    workspace_id INTEGER      NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    name         VARCHAR(80)  NOT NULL,
    description  TEXT,
    channel_type VARCHAR(10)  NOT NULL DEFAULT 'public'
                              CHECK (channel_type IN ('public','private','direct')),
    created_by   INTEGER      NOT NULL REFERENCES users(user_id),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, name)
);

CREATE TABLE channel_members (
    channel_id INTEGER     NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    user_id    INTEGER     NOT NULL REFERENCES users(user_id)    ON DELETE CASCADE,
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, user_id)
);

CREATE TABLE channel_invitations (
    invitation_id   SERIAL PRIMARY KEY,
    channel_id      INTEGER     NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    invited_by      INTEGER     NOT NULL REFERENCES users(user_id),
    invited_user_id INTEGER     NOT NULL REFERENCES users(user_id),
    status          VARCHAR(10) NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending','accepted','declined')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (channel_id, invited_user_id)
);

CREATE TABLE messages (
    message_id SERIAL PRIMARY KEY,
    channel_id INTEGER     NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    user_id    INTEGER     NOT NULL REFERENCES users(user_id),
    content    TEXT        NOT NULL CHECK (char_length(content) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edited_at  TIMESTAMPTZ
);

-- File attachments linked to a message (one message can have one attachment)
CREATE TABLE message_attachments (
    attachment_id   SERIAL PRIMARY KEY,
    message_id      INTEGER       NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    original_name   VARCHAR(255)  NOT NULL,   -- original filename from user's device
    stored_name     VARCHAR(255)  NOT NULL UNIQUE, -- uuid-based name on disk
    mime_type       VARCHAR(100)  NOT NULL,
    file_size_bytes INTEGER       NOT NULL,
    uploaded_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────
-- Extra-credit feature tables
-- ─────────────────────────────────────────

-- Emoji reactions: one row per (message, user, emoji) triple
CREATE TABLE message_reactions (
    message_id  INTEGER      NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    user_id     INTEGER      NOT NULL REFERENCES users(user_id)       ON DELETE CASCADE,
    emoji       VARCHAR(10)  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (message_id, user_id, emoji)
);

-- Track the last time each user read each channel (drives unread badges)
CREATE TABLE channel_last_read (
    channel_id   INTEGER     NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    user_id      INTEGER     NOT NULL REFERENCES users(user_id)       ON DELETE CASCADE,
    last_read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, user_id)
);

-- Pinned messages: at most one pin record per (channel, message)
CREATE TABLE pinned_messages (
    channel_id  INTEGER     NOT NULL REFERENCES channels(channel_id)  ON DELETE CASCADE,
    message_id  INTEGER     NOT NULL REFERENCES messages(message_id)  ON DELETE CASCADE,
    pinned_by   INTEGER     NOT NULL REFERENCES users(user_id),
    pinned_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, message_id)
);

-- ─────────────────────────────────────────
-- Indexes
-- ─────────────────────────────────────────
CREATE INDEX idx_messages_channel   ON messages(channel_id, created_at);
CREATE INDEX idx_messages_user      ON messages(user_id);
CREATE INDEX idx_messages_content   ON messages USING gin(to_tsvector('english', content));
CREATE INDEX idx_channels_workspace ON channels(workspace_id);
CREATE INDEX idx_wm_user            ON workspace_members(user_id);
CREATE INDEX idx_reactions_message  ON message_reactions(message_id);
CREATE INDEX idx_last_read_user     ON channel_last_read(user_id);
CREATE INDEX idx_pinned_channel     ON pinned_messages(channel_id);
CREATE INDEX idx_attachments_msg    ON message_attachments(message_id);
CREATE INDEX idx_ws_inv_user        ON workspace_invitations(invited_user_id);
CREATE INDEX idx_ws_inv_workspace   ON workspace_invitations(workspace_id);

-- ─────────────────────────────────────────
-- Stored procedures
-- ─────────────────────────────────────────

-- Register a new user (returns user_id)
CREATE OR REPLACE FUNCTION sp_register_user(
    p_username      VARCHAR,
    p_email         VARCHAR,
    p_nickname      VARCHAR,
    p_password_hash VARCHAR
) RETURNS INTEGER AS $$
DECLARE v_id INTEGER;
BEGIN
    INSERT INTO users(username, email, nickname, password_hash)
    VALUES (p_username, p_email, p_nickname, p_password_hash)
    RETURNING user_id INTO v_id;
    RETURN v_id;
END;
$$ LANGUAGE plpgsql;

-- Create workspace and auto-add creator as admin
CREATE OR REPLACE FUNCTION sp_create_workspace(
    p_name        VARCHAR,
    p_description TEXT,
    p_user_id     INTEGER
) RETURNS INTEGER AS $$
DECLARE v_ws INTEGER;
BEGIN
    INSERT INTO workspaces(name, description, created_by)
    VALUES (p_name, p_description, p_user_id)
    RETURNING workspace_id INTO v_ws;

    INSERT INTO workspace_members(workspace_id, user_id, is_admin)
    VALUES (v_ws, p_user_id, TRUE);

    -- create a default #general channel
    INSERT INTO channels(workspace_id, name, description, channel_type, created_by)
    VALUES (v_ws, 'general', 'General discussion', 'public', p_user_id);

    RETURN v_ws;
END;
$$ LANGUAGE plpgsql;

-- Post a message (user must be a member)
CREATE OR REPLACE FUNCTION sp_post_message(
    p_channel_id INTEGER,
    p_user_id    INTEGER,
    p_content    TEXT
) RETURNS INTEGER AS $$
DECLARE v_msg INTEGER;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM channel_members
        WHERE channel_id = p_channel_id AND user_id = p_user_id
    ) THEN
        RAISE EXCEPTION 'User is not a member of this channel';
    END IF;

    INSERT INTO messages(channel_id, user_id, content)
    VALUES (p_channel_id, p_user_id, p_content)
    RETURNING message_id INTO v_msg;
    RETURN v_msg;
END;
$$ LANGUAGE plpgsql;

-- Accept or decline a channel invitation
CREATE OR REPLACE FUNCTION sp_respond_invitation(
    p_invitation_id INTEGER,
    p_user_id       INTEGER,
    p_accept        BOOLEAN
) RETURNS VOID AS $$
DECLARE
    v_channel_id INTEGER;
    v_status     VARCHAR;
    v_channel_type VARCHAR;
    v_workspace_id INTEGER;
    v_invited_by INTEGER;
    v_created_by INTEGER;
BEGIN
    SELECT ci.channel_id, ci.status, c.channel_type, c.workspace_id, ci.invited_by, c.created_by
    INTO v_channel_id, v_status, v_channel_type, v_workspace_id, v_invited_by, v_created_by
    FROM channel_invitations ci
    JOIN channels c ON c.channel_id = ci.channel_id
    WHERE ci.invitation_id = p_invitation_id
      AND ci.invited_user_id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invitation not found';
    END IF;
    IF v_status <> 'pending' THEN
        RAISE EXCEPTION 'Invitation already responded to';
    END IF;
    IF v_channel_type = 'direct' THEN
        RAISE EXCEPTION 'Direct channels cannot be joined by invitation';
    END IF;
    IF v_channel_type = 'private' AND v_invited_by <> v_created_by THEN
        RAISE EXCEPTION 'Private channel invitations must be sent by the channel creator';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM workspace_members
        WHERE workspace_id = v_workspace_id AND user_id = p_user_id
    ) THEN
        RAISE EXCEPTION 'User must be a workspace member to join this channel';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM workspace_members
        WHERE workspace_id = v_workspace_id AND user_id = v_invited_by
    ) THEN
        RAISE EXCEPTION 'Inviter must be a workspace member';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM channel_members
        WHERE channel_id = v_channel_id AND user_id = v_invited_by
    ) THEN
        RAISE EXCEPTION 'Inviter must be a channel member';
    END IF;

    IF p_accept THEN
        UPDATE channel_invitations SET status = 'accepted'
        WHERE invitation_id = p_invitation_id;

        INSERT INTO channel_members(channel_id, user_id)
        VALUES (v_channel_id, p_user_id)
        ON CONFLICT DO NOTHING;
    ELSE
        UPDATE channel_invitations SET status = 'declined'
        WHERE invitation_id = p_invitation_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Accept or decline a workspace invitation
CREATE OR REPLACE FUNCTION sp_respond_workspace_invitation(
    p_invitation_id INTEGER,
    p_user_id       INTEGER,
    p_accept        BOOLEAN
) RETURNS VOID AS $$
DECLARE
    v_workspace_id INTEGER;
    v_status       VARCHAR;
    v_general_id   INTEGER;
BEGIN
    SELECT workspace_id, status INTO v_workspace_id, v_status
    FROM workspace_invitations
    WHERE invitation_id = p_invitation_id AND invited_user_id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Workspace invitation not found';
    END IF;
    IF v_status <> 'pending' THEN
        RAISE EXCEPTION 'Invitation already responded to';
    END IF;

    IF p_accept THEN
        UPDATE workspace_invitations SET status = 'accepted'
        WHERE invitation_id = p_invitation_id;

        INSERT INTO workspace_members(workspace_id, user_id)
        VALUES (v_workspace_id, p_user_id)
        ON CONFLICT DO NOTHING;

        -- Auto-join the #general channel if it exists
        SELECT channel_id INTO v_general_id
        FROM channels
        WHERE workspace_id = v_workspace_id AND name = 'general';

        IF FOUND THEN
            INSERT INTO channel_members(channel_id, user_id)
            VALUES (v_general_id, p_user_id)
            ON CONFLICT DO NOTHING;
        END IF;
    ELSE
        UPDATE workspace_invitations SET status = 'declined'
        WHERE invitation_id = p_invitation_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Full-text search across accessible messages
CREATE OR REPLACE FUNCTION sp_search_messages(
    p_user_id    INTEGER,
    p_query      TEXT,
    p_workspace_id INTEGER DEFAULT NULL
) RETURNS TABLE (
    message_id   INTEGER,
    channel_id   INTEGER,
    channel_name VARCHAR,
    workspace_id INTEGER,
    workspace_name VARCHAR,
    author       VARCHAR,
    content      TEXT,
    created_at   TIMESTAMPTZ
) AS $$
BEGIN
    RETURN QUERY
    SELECT m.message_id, m.channel_id, c.name::VARCHAR, c.workspace_id,
           w.name::VARCHAR, u.username::VARCHAR, m.content, m.created_at
    FROM messages m
    JOIN channels c              ON c.channel_id   = m.channel_id
    JOIN workspaces w            ON w.workspace_id = c.workspace_id
    JOIN users u                 ON u.user_id      = m.user_id
    JOIN workspace_members wm    ON wm.workspace_id = c.workspace_id
                                  AND wm.user_id = p_user_id
    LEFT JOIN channel_members cm ON cm.channel_id  = m.channel_id
                                  AND cm.user_id = p_user_id
    WHERE to_tsvector('english', m.content) @@ plainto_tsquery('english', p_query)
      AND (p_workspace_id IS NULL OR c.workspace_id = p_workspace_id)
      AND (c.channel_type = 'public' OR cm.user_id IS NOT NULL)
    ORDER BY m.created_at DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- Sample Data  (CS6083 Project 2 — snickr)
--
-- Designed to exercise all 7 required SQL queries plus new features:
--   Q1  CREATE USER          → sp_register_user / INSERT INTO users
--   Q2  CREATE CHANNEL       → INSERT INTO channels (any workspace member)
--   Q3  LIST ADMINS          → workspace_members WHERE is_admin = TRUE
--   Q4  STALE INVITES        → channel_invitations WHERE created_at < NOW()-5d
--                              AND status='pending' AND public channel
--   Q5  CHANNEL MESSAGES     → messages WHERE channel_id = X ORDER BY created_at
--   Q6  USER'S MESSAGES      → messages WHERE user_id = X (across channels)
--   Q7  KEYWORD SEARCH       → messages WHERE content ILIKE '%perpendicular%'
--                              AND user is workspace+channel member
--
-- New features:
--   • Registration with nickname     → users.nickname column
--   • Editable user profiles         → UPDATE users SET nickname/email
--   • Workspace invitations          → workspace_invitations table
--   • Admin removes members          → DELETE FROM workspace_members
--   • Owner promotes to admin        → UPDATE workspace_members SET is_admin
--   • Any member creates channels    → no admin check in app
--
-- IDs (all SERIAL, so determined by insert order):
--   users       : alice=1  bob=2  carol=3  dave=4  eve=5  frank=6  grace=7  hank=8
--   workspaces  : TechCorp=1  CoopBoard=2
--   channels    : general=1  random=2  hiring=3  alice-bob-dm=4
--                 announcements=5  maintenance=6  design=7
-- ============================================================


-- ------------------------------------------------------------
-- 1. USERS
--    All passwords are werkzeug scrypt hashes of 'password123'
--    (Q1 demo: registering a new user via the web UI calls
--     sp_register_user, which does the same INSERT below)
--    Nicknames demonstrate the new registration field.
-- ------------------------------------------------------------
INSERT INTO users (username, email, nickname, password_hash) VALUES
  ('alice99', 'alice@techcorp.com',  'Alice',   'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3'),
  ('bobby_b', 'bob@techcorp.com',    'Bob',     'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3'),
  ('carol_c', 'carol@example.com',   'Carol',   'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3'),
  ('dave_d',  'dave@techcorp.com',   'Dave',    'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3'),
  ('eve_e',   'eve@example.com',     'Eve',     'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3'),
  ('frank_f', 'frank@cooboard.com',  'Frank',   'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3'),
  ('grace_g', 'grace@techcorp.com',  'Grace',   'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3'),
  ('hank_h',  'hank@example.com',    'Hank',    'scrypt:32768:8:1$upFXaiQq8VMJVOmf$a745fb8d63768bebcbd737c3295f138922e8ae3308afa670896e726aaa582449e5f0e27e4afeb41cd5cbd725e5dbf5493715165e196270da59d78f4981bdb3f3');


-- ------------------------------------------------------------
-- 2. WORKSPACES
--    TechCorp: company-internal engineering workspace
--    CoopBoard: building co-op board communication
-- ------------------------------------------------------------
INSERT INTO workspaces (name, description, created_by) VALUES
  ('TechCorp',  'Internal workspace for TechCorp employees', 1),  -- ws 1, created by alice
  ('CoopBoard', 'Building co-op board communication',        2);  -- ws 2, created by bob


-- ------------------------------------------------------------
-- 3. WORKSPACE MEMBERS
--    Q3 test: TechCorp has TWO admins (alice + bob)
--             CoopBoard has TWO admins (bob + frank)
--             bob is admin in BOTH workspaces — interesting case
-- ------------------------------------------------------------
INSERT INTO workspace_members (workspace_id, user_id, is_admin) VALUES
  -- TechCorp
  (1, 1, TRUE),   -- alice  (admin, creator/owner)
  (1, 2, TRUE),   -- bob    (admin)
  (1, 3, FALSE),  -- carol
  (1, 4, FALSE),  -- dave
  (1, 5, FALSE),  -- eve

  -- CoopBoard
  (2, 2, TRUE),   -- bob    (admin, creator/owner)
  (2, 6, TRUE),   -- frank  (admin)
  (2, 5, FALSE);  -- eve    (regular member)


-- ------------------------------------------------------------
-- 4. WORKSPACE INVITATIONS
--    Demonstrates the invite → accept/decline workflow.
--    • grace invited to TechCorp by alice — pending (user can accept/decline)
--    • hank invited to TechCorp by bob — pending
--    • grace invited to CoopBoard by bob — accepted (already joined)
--    • hank invited to CoopBoard by frank — declined
-- ------------------------------------------------------------
INSERT INTO workspace_invitations (workspace_id, invited_by, invited_user_id, status, created_at) VALUES
  -- grace invited to TechCorp by alice, 3 days ago — pending
  (1, 1, 7, 'pending',  NOW() - INTERVAL '3 days'),

  -- hank invited to TechCorp by bob, 1 day ago — pending
  (1, 2, 8, 'pending',  NOW() - INTERVAL '1 day'),

  -- grace invited to CoopBoard by bob, 5 days ago — accepted
  (2, 2, 7, 'accepted', NOW() - INTERVAL '5 days'),

  -- hank invited to CoopBoard by frank, 4 days ago — declined
  (2, 6, 8, 'declined', NOW() - INTERVAL '4 days');

-- grace is already a CoopBoard member (accepted invitation above)
INSERT INTO workspace_members (workspace_id, user_id, is_admin) VALUES
  (2, 7, FALSE);  -- grace (accepted invite to CoopBoard)


-- ------------------------------------------------------------
-- 5. CHANNELS
--    TechCorp : #general (public), #random (public),
--               #hiring (private), alice-bob-dm (direct),
--               #design (public, created by carol — non-admin)
--    CoopBoard: #announcements (public), #maintenance (private)
--
--    Q2 test: any workspace member may create channels (enforced in app.py)
--    The direct channel tests the 'direct' CHECK constraint.
--    #design shows that non-admin carol can create channels.
-- ------------------------------------------------------------
INSERT INTO channels (workspace_id, name, description, channel_type, created_by) VALUES
  (1, 'general',       'General TechCorp discussion',        'public',  1),  -- ch 1
  (1, 'random',        'Off-topic and watercooler chat',     'public',  2),  -- ch 2
  (1, 'hiring',        'Confidential hiring discussions',    'private', 1),  -- ch 3
  (1, 'alice-bob-dm',  'Direct messages: Alice and Bob',     'direct',  1),  -- ch 4
  (2, 'announcements', 'Official co-op board announcements', 'public',  2),  -- ch 5
  (2, 'maintenance',   'Building maintenance coordination',  'private', 6),  -- ch 6
  (1, 'design',        'UI/UX design discussion',            'public',  3);  -- ch 7 (created by carol, non-admin)


-- ------------------------------------------------------------
-- 6. CHANNEL MEMBERS
--    #random has only alice+bob joined — carol and eve were
--    invited but have NOT accepted yet (see invitations below).
--    This is the key setup for Q4.
-- ------------------------------------------------------------
INSERT INTO channel_members (channel_id, user_id) VALUES
  -- #general (ch 1): all TechCorp members
  (1, 1), (1, 2), (1, 3), (1, 4), (1, 5),

  -- #random (ch 2): alice and bob only (carol/eve invited, not joined)
  (2, 1), (2, 2),

  -- #hiring (ch 3): alice and dave only (private)
  (3, 1), (3, 4),

  -- alice-bob-dm (ch 4): alice and bob only
  (4, 1), (4, 2),

  -- #announcements (ch 5): all CoopBoard members
  (5, 2), (5, 5), (5, 6), (5, 7),

  -- #maintenance (ch 6): bob and frank only (private)
  (6, 2), (6, 6),

  -- #design (ch 7): carol (creator) and alice
  (7, 3), (7, 1);


-- ------------------------------------------------------------
-- 7. CHANNEL INVITATIONS
--
--    Q4 test cases (public channels, invited_user NOT in channel_members):
--      ✓ HIT  : carol → #random, invited 6 days ago, still pending
--      ✗ MISS : eve   → #random, invited 2 days ago (< 5 days threshold)
--
--    Additional cases (should NOT appear in Q4):
--      • dave → #hiring: 10 days ago but channel is PRIVATE → excluded
--      • carol → #random accepted case below would remove from Q4 result
--        (we keep carol pending to show the count = 1 for #random)
-- ------------------------------------------------------------
INSERT INTO channel_invitations (channel_id, invited_by, invited_user_id, status, created_at) VALUES
  -- carol invited to #random by bob, 6 days ago — pending (Q4 HIT)
  (2, 2, 3, 'pending',  NOW() - INTERVAL '6 days'),

  -- eve invited to #random by alice, 2 days ago — pending (Q4 MISS: too recent)
  (2, 1, 5, 'pending',  NOW() - INTERVAL '2 days'),

  -- dave invited to #hiring by alice, 10 days ago — accepted (joined, so not pending)
  -- This also tests that PRIVATE channels are excluded from Q4
  (3, 1, 4, 'accepted', NOW() - INTERVAL '10 days');


-- ------------------------------------------------------------
-- 8. MESSAGES
--    Column mapping (new schema):
--      user_id  (was sender_id)
--      content  (was body)
--      created_at (was posted_at, now TIMESTAMPTZ with explicit value)
--
--    Q5 test: fetch all messages for a given channel ordered by time
--    Q6 test: alice posts in #general, #hiring, and alice-bob-dm
--             → her messages span 3 channels
--    Q7 test: TWO messages contain "perpendicular"
--      • carol's message in #general (ch 1)  — accessible to all general members
--      • alice's message in #hiring  (ch 3)  — accessible ONLY to alice and dave
--        carol is NOT a member of #hiring, so she must NOT see that message
--        when her Q7 results are returned — good exclusion test case
-- ------------------------------------------------------------
INSERT INTO messages (channel_id, user_id, content, created_at) VALUES

  -- #general (ch 1) — chronological order tests Q5
  (1, 1, 'Welcome everyone to the TechCorp workspace!',
      NOW() - INTERVAL '10 days'),
  (1, 2, 'Thanks Alice — great to have a proper comms tool at last.',
      NOW() - INTERVAL '9 days'),
  (1, 3, 'Has anyone worked with perpendicular data structures before? Trying to model a grid graph.',
      NOW() - INTERVAL '8 days'),   -- "perpendicular" — visible to all #general members (Q7)
  (1, 4, 'Carol — yes! Happy to pair on that. Let us sync tomorrow.',
      NOW() - INTERVAL '8 days'),
  (1, 5, 'Looking forward to collaborating with everyone here.',
      NOW() - INTERVAL '7 days'),
  (1, 1, 'Reminder: all-hands meeting is Friday at 10 AM.',
      NOW() - INTERVAL '3 days'),   -- alice posts twice in #general (Q6 test)

  -- #random (ch 2)
  (2, 1, 'Anyone catch the game last night?',
      NOW() - INTERVAL '5 days'),
  (2, 2, 'Yes! What an ending — could not believe it.',
      NOW() - INTERVAL '5 days'),

  -- #hiring (ch 3) — private; only alice and dave can see these
  (3, 1, 'We have three strong candidates for the senior engineer role. The skill matrix is almost perpendicular to what we saw last cycle.',
      NOW() - INTERVAL '4 days'),   -- "perpendicular" in PRIVATE channel (Q7 exclusion test)
  (3, 4, 'Agreed — candidate B stands out clearly. Want me to schedule the final round?',
      NOW() - INTERVAL '3 days'),

  -- alice-bob-dm (ch 4) — direct
  (4, 1, 'Bob, can you review the Q3 budget report before Friday?',
      NOW() - INTERVAL '2 days'),
  (4, 2, 'Sure, I will have notes to you by Thursday morning.',
      NOW() - INTERVAL '2 days'),

  -- #announcements (ch 5) — CoopBoard public
  (5, 2, 'Board meeting is scheduled for next Monday at 7 PM in the lobby.',
      NOW() - INTERVAL '6 days'),
  (5, 6, 'I will send the agenda and minutes template by Sunday.',
      NOW() - INTERVAL '5 days'),
  (5, 5, 'Thanks Frank — see you all there.',
      NOW() - INTERVAL '4 days'),

  -- #maintenance (ch 6) — CoopBoard private
  (6, 6, 'The boiler inspection is overdue — contractor confirmed for Thursday.',
      NOW() - INTERVAL '3 days'),
  (6, 2, 'Good. I will make sure the basement is accessible.',
      NOW() - INTERVAL '2 days'),

  -- #design (ch 7) — created by carol (non-admin), TechCorp
  (7, 3, 'I have been working on the new dashboard wireframes. Thoughts?',
      NOW() - INTERVAL '1 day'),
  (7, 1, 'Looks great Carol! Love the sidebar layout.',
      NOW() - INTERVAL '12 hours');
