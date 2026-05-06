-- snickr schema (CS6083 Project 2)
-- Drop in reverse dependency order
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS channel_invitations CASCADE;
DROP TABLE IF EXISTS channel_members CASCADE;
DROP TABLE IF EXISTS channels CASCADE;
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

-- ─────────────────────────────────────────
-- Indexes
-- ─────────────────────────────────────────
CREATE INDEX idx_messages_channel   ON messages(channel_id, created_at);
CREATE INDEX idx_messages_user      ON messages(user_id);
CREATE INDEX idx_messages_content   ON messages USING gin(to_tsvector('english', content));
CREATE INDEX idx_channels_workspace ON channels(workspace_id);
CREATE INDEX idx_wm_user            ON workspace_members(user_id);

-- ─────────────────────────────────────────
-- Stored procedures
-- ─────────────────────────────────────────

-- Register a new user (returns user_id)
CREATE OR REPLACE FUNCTION sp_register_user(
    p_username      VARCHAR,
    p_email         VARCHAR,
    p_password_hash VARCHAR
) RETURNS INTEGER AS $$
DECLARE v_id INTEGER;
BEGIN
    INSERT INTO users(username, email, password_hash)
    VALUES (p_username, p_email, p_password_hash)
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

-- Accept or decline an invitation
CREATE OR REPLACE FUNCTION sp_respond_invitation(
    p_invitation_id INTEGER,
    p_user_id       INTEGER,
    p_accept        BOOLEAN
) RETURNS VOID AS $$
DECLARE
    v_channel_id INTEGER;
    v_status     VARCHAR;
BEGIN
    SELECT channel_id, status INTO v_channel_id, v_status
    FROM channel_invitations
    WHERE invitation_id = p_invitation_id AND invited_user_id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invitation not found';
    END IF;
    IF v_status <> 'pending' THEN
        RAISE EXCEPTION 'Invitation already responded to';
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
    JOIN channels c         ON c.channel_id   = m.channel_id
    JOIN workspaces w       ON w.workspace_id = c.workspace_id
    JOIN users u            ON u.user_id      = m.user_id
    JOIN channel_members cm ON cm.channel_id  = m.channel_id AND cm.user_id = p_user_id
    WHERE to_tsvector('english', m.content) @@ plainto_tsquery('english', p_query)
      AND (p_workspace_id IS NULL OR c.workspace_id = p_workspace_id)
    ORDER BY m.created_at DESC;
END;
$$ LANGUAGE plpgsql;

-- ─────────────────────────────────────────
-- Sample data
-- ─────────────────────────────────────────
-- Passwords are bcrypt hashes of 'password123'
INSERT INTO users (username, email, password_hash) VALUES
('alice',   'alice@example.com',   '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9i'),
('bob',     'bob@example.com',     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9i'),
('carol',   'carol@example.com',   '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9i'),
('dave',    'dave@example.com',    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9i'),
('eve',     'eve@example.com',     '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9i'),
('frank',   'frank@example.com',   '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9i');

SELECT sp_create_workspace('Acme Engineering', 'Main engineering workspace', 1);  -- ws 1
SELECT sp_create_workspace('Research Lab',     'ML and data research team',  3);  -- ws 2

-- Add members to workspace 1
INSERT INTO workspace_members(workspace_id, user_id, is_admin) VALUES
(1, 2, FALSE),(1, 4, FALSE),(1, 5, TRUE),(1, 6, FALSE);

-- Add members to workspace 2
INSERT INTO workspace_members(workspace_id, user_id, is_admin) VALUES
(2, 1, FALSE),(2, 6, FALSE),(2, 5, FALSE);

-- Channels in workspace 1
INSERT INTO channels(workspace_id, name, description, channel_type, created_by) VALUES
(1, 'backend',   'Backend engineering',        'public',  1),
(1, 'frontend',  'UI/UX and frontend work',    'public',  2),
(1, 'ops',       'Infrastructure and DevOps',  'private', 4),
(1, 'random',    'Watercooler chat',            'public',  5);

-- Channels in workspace 2
INSERT INTO channels(workspace_id, name, description, channel_type, created_by) VALUES
(2, 'papers',    'Paper discussion',           'public',  3),
(2, 'datasets',  'Dataset sharing',            'public',  6);

-- Channel memberships
INSERT INTO channel_members(channel_id, user_id) VALUES
-- general (ch 1), backend (ch 2), frontend (ch 3), ops (ch 4), random (ch 5)
(1,1),(1,2),(1,4),(1,5),(1,6),
(2,1),(2,4),(2,6),
(3,2),(3,5),
(4,1),(4,4),
(5,1),(5,2),(5,4),(5,5),(5,6),
-- ws2: general (ch 6), papers (ch 7), datasets (ch 8)
(6,1),(6,3),(6,5),(6,6),
(7,3),(7,6),(7,1),
(8,3),(8,6);

-- Messages
INSERT INTO messages(channel_id, user_id, content) VALUES
(1,1,'Welcome to snickr! 🎉'),
(1,2,'Hey everyone, glad to be here!'),
(2,1,'Just deployed the new auth service.'),
(2,4,'Looks good, monitoring dashboards are green.'),
(2,6,'The latency is perpendicular to what we expected — worth investigating.'),
(3,2,'New design system PR is up for review.'),
(5,5,'Anyone up for lunch tomorrow?'),
(5,2,'Absolutely, the usual spot?'),
(6,3,'Kicking off the new research cycle.'),
(7,3,'Has anyone read the new transformer efficiency paper?'),
(7,6,'Yes! The results are surprisingly perpendicular to prior benchmarks.'),
(8,3,'Uploading the cleaned MNIST variant.');

-- Pending invitation
INSERT INTO channel_invitations(channel_id, invited_by, invited_user_id, status) VALUES
(4, 1, 2, 'pending'),
(7, 3, 5, 'pending');
