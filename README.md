# snickr – CS6083 Project 2

A Slack-like team messaging web app built with Flask + PostgreSQL.

## Quick start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create the database
createdb snickr

# 3. Load schema + sample data
psql snickr < schema.sql

# 4. Configure environment
cp .env.example .env
# Edit .env → set DB_PASSWORD and SECRET_KEY

# 5. Run
python app.py
# Open http://localhost:5000
```

## Sample accounts (all passwords: `password123`)

| Username | Role          |
|----------|---------------|
| alice    | Engineering admin |
| bob      | Frontend dev  |
| carol    | Research admin |
| dave     | DevOps        |
| eve      | PM            |
| frank    | ML researcher |

## Security measures

| Threat | Mitigation |
|--------|-----------|
| SQL Injection | 100% parameterised queries via psycopg2 `%s` placeholders |
| XSS | Jinja2 auto-escaping (all variables escaped by default) |
| CSRF | Synchroniser token on every state-changing POST form |
| Password storage | bcrypt via `werkzeug.security.generate_password_hash` |
| Session hijacking | Flask server-side sessions with `SECRET_KEY` |
| Concurrency | Explicit transactions; stored procedures run atomically |

## Features

- Register / login / logout  
- Create workspaces (auto-creates #general, creator is admin)  
- Browse workspace channels; join public channels  
- Post, edit, delete messages  
- Invite workspace members to private channels  
- Accept / decline channel invitations  
- Full-text message search (PostgreSQL GIN index)  
- Bookmarkable URLs for every workspace, channel, and search  
- Profile editing  
