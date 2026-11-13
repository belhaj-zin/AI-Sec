# Notes API

A small FastAPI notes service with JWT authentication and SQLite persistence.

## Requirements

- Python 3.12+
- Docker and Docker Compose (recommended)

## Run with Docker Compose

Create a local environment file:

```bash
cp .env.example .env
```

Replace the example `JWT_SECRET` with a long random value. Do not commit `.env`.

Build and start the service:

```bash
docker compose up --build
```

The API is available at <http://localhost:8000>. The SQLite database is
persisted in `./data/notes.db`, which is ignored by Git.

Stop the service:

```bash
docker compose down
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
export JWT_SECRET="replace-this-with-a-long-random-secret"
uvicorn notes_api:app --reload
```

## Run tests

```bash
pytest -q
```

Tests use a temporary SQLite database and do not modify the runtime database.

## API flow

Register and log in:

```bash
curl -X POST "http://localhost:8000/register?username=alice&password=change-me"
curl -X POST "http://localhost:8000/login?username=alice&password=change-me"
```

Use the returned token for protected endpoints:

```bash
curl "http://localhost:8000/list_notes" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Protected endpoints include creating, listing, reading, and deleting notes.
Each query is restricted to the authenticated user's `user_id`.

## Security notes

This educational example currently stores passwords in plaintext despite the
`password_hash` column name. Do not use it as-is in production; replace this
with a standard password-hashing library and use HTTPS.
