# snickr – CS6083 Project 2

A **Slack-inspired team messaging web application** built with **Flask** and **PostgreSQL**.  
Users can create workspaces, organise channels, send messages with file attachments, react with emoji, pin important messages, and search across conversations — all with a polished dark-mode UI.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Sample Accounts](#sample-accounts)
- [Features](#features)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [Stored Procedures](#stored-procedures)
- [Security Measures](#security-measures)
- [Tech Stack](#tech-stack)

---

## Quick Start

### Prerequisites

- **Python 3.10+**
- **PostgreSQL 14+**

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/adhyayanverma/snickr.git
cd snickr

# 2. Create and activate a virtual environment
python -m venv venv
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create the database
createdb snickr

# 5. Load schema + sample data
psql snickr < schema.sql

# 6. Configure environment variables
cp .env.example .env
# Edit .env → set DB_PASSWORD and SECRET_KEY

# 7. Run the application
python app.py
# Open http://localhost:5000
```

---

## Sample Accounts

All sample accounts use the password **`password123`**.

| Username    | Email                  | Workspaces                    | Role             |
| ----------- | ---------------------- | ----------------------------- | ---------------- |
| `alice99`   | alice@techcorp.com     | TechCorp                      | Admin            |
| `bobby_b`   | bob@techcorp.com       | TechCorp, CoopBoard           | Admin (both)     |
| `carol_c`   | carol@example.com      | TechCorp                      | Member           |
| `dave_d`    | dave@techcorp.com      | TechCorp                      | Member           |
| `eve_e`     | eve@example.com        | TechCorp, CoopBoard           | Member           |
| `frank_f`   | frank@cooboard.com     | CoopBoard                     | Admin            |

---

## Features

### Core

- **User Authentication** — Register, login, logout with secure password hashing
- **Workspaces** — Create workspaces; creator is auto-added as admin with a default `#general` channel
- **Channels** — Public, private, and direct message channel types
- **Messaging** — Post, edit, and delete messages in real time with `@mention` highlighting
- **Channel Invitations** — Invite workspace members to channels; accept or decline pending invitations
- **Full-Text Search** — Search messages across all accessible channels using PostgreSQL GIN indexes, with optional workspace filtering
- **Profile Page** — View account details

### Extra Credit

- **📎 File Attachments** — Upload images, PDFs, code files, and more (max 10 MB); inline image previews with a lightbox viewer
- **😀 Emoji Reactions** — React to messages with 10 supported emoji; toggle reactions on/off
- **📌 Pinned Messages** — Pin important messages to a channel; view all pins in a dedicated modal
- **🔴 Unread Badges** — Channels display unread message counts based on per-user read tracking

### Admin Features

- Add members to workspaces (auto-joins `#general`)
- Create new channels (public or private)
- Delete any message within the workspace

---

## Project Structure

```
snickr/
├── app.py                 # Flask application (routes, DB helpers, auth)
├── schema.sql             # PostgreSQL schema, stored procedures, sample data
├── requirements.txt       # Python dependencies
├── .env.example           # Environment variable template
├── .gitignore
├── README.md
├── static/
│   └── uploads/           # User-uploaded file attachments
└── templates/
    ├── base.html           # Base layout with sidebar, topbar, flash messages
    ├── login.html          # Login page
    ├── register.html       # Registration page
    ├── dashboard.html      # Workspace overview
    ├── workspace.html      # Workspace detail (channels, members, unread badges)
    ├── channel.html        # Channel view (messages, reactions, pins, attachments)
    ├── new_workspace.html  # Create workspace form
    ├── new_channel.html    # Create channel form
    ├── invitations.html    # Pending invitations list
    ├── search.html         # Full-text search interface
    ├── profile.html        # User profile page
    └── error.html          # Error pages (403, 404)
```

---

## Database Schema

### Entity-Relationship Overview

```
users ──┬── workspace_members ──── workspaces
        │         │
        │   channel_members ────── channels ──── pinned_messages
        │         │                    │
        │   channel_invitations        │
        │                              │
        ├── messages ──────────────────┘
        │      ├── message_attachments
        │      └── message_reactions
        └── channel_last_read
```

### Tables

| Table                  | Description                                                  |
| ---------------------- | ------------------------------------------------------------ |
| `users`                | User accounts (username, email, password hash)               |
| `workspaces`           | Workspace containers with name, description, creator         |
| `workspace_members`    | M:N — users ↔ workspaces, with `is_admin` flag               |
| `channels`             | Channels within workspaces (`public`, `private`, `direct`)   |
| `channel_members`      | M:N — users ↔ channels                                       |
| `channel_invitations`  | Invitation system with `pending`/`accepted`/`declined` status |
| `messages`             | Chat messages with content, timestamps, edit tracking        |
| `message_attachments`  | File uploads linked to messages (1:1)                        |
| `message_reactions`    | Emoji reactions per message per user                         |
| `channel_last_read`    | Tracks last-read timestamp per user per channel              |
| `pinned_messages`      | Pinned message records per channel                           |

### Indexes

| Index                       | Type   | Purpose                          |
| --------------------------- | ------ | -------------------------------- |
| `idx_messages_channel`      | B-tree | Fast message retrieval by channel |
| `idx_messages_user`         | B-tree | User message history             |
| `idx_messages_content`      | GIN    | Full-text search on messages     |
| `idx_channels_workspace`    | B-tree | Channel listing per workspace    |
| `idx_wm_user`               | B-tree | Workspace lookups by user        |
| `idx_reactions_message`     | B-tree | Reaction aggregation             |
| `idx_last_read_user`        | B-tree | Unread count computation         |
| `idx_pinned_channel`        | B-tree | Pinned message queries           |
| `idx_attachments_msg`       | B-tree | Attachment lookups by message    |

---

## Stored Procedures

| Procedure                 | Description                                                          |
| ------------------------- | -------------------------------------------------------------------- |
| `sp_register_user`        | Inserts a new user and returns the `user_id`                         |
| `sp_create_workspace`     | Creates a workspace, adds creator as admin, auto-creates `#general`  |
| `sp_post_message`         | Posts a message after verifying channel membership                   |
| `sp_respond_invitation`   | Accepts or declines a channel invitation; auto-adds member on accept |
| `sp_search_messages`      | Full-text search scoped to channels the user has access to           |

---

## Security Measures

| Threat              | Mitigation                                                               |
| ------------------- | ------------------------------------------------------------------------ |
| SQL Injection       | 100% parameterised queries via psycopg2 `%s` placeholders               |
| XSS                 | Jinja2 auto-escaping on all templates (enabled by default in Flask)      |
| CSRF                | Synchroniser token verified on every state-changing POST form            |
| Password Storage    | Scrypt hashing via `werkzeug.security.generate_password_hash`            |
| Session Hijacking   | Flask server-side sessions with cryptographic `SECRET_KEY`               |
| Concurrency         | Explicit transactions; stored procedures run atomically                  |
| File Uploads        | Allowlist of extensions, 10 MB size cap, UUID-renamed files on disk      |
| Path Traversal      | `secure_filename` sanitisation + traversal checks on attachment serving  |
| Access Control      | Channel membership verified before message viewing and file downloads    |

---

## Tech Stack

| Layer     | Technology                                          |
| --------- | --------------------------------------------------- |
| Backend   | Python 3, Flask 3.0                                 |
| Database  | PostgreSQL 14+ with PL/pgSQL stored procedures      |
| ORM       | None — raw SQL with psycopg2 (parameterised queries) |
| Templates | Jinja2 (server-side rendering)                      |
| Styling   | Vanilla CSS (dark theme with CSS custom properties)  |
| Auth      | Werkzeug (scrypt password hashing)                   |
