"""
Tests for the Notes API (version with POST for state-changing endpoints,
string `sub` in the JWT, and query-string parameters).

Keep APP_MODULE set to your app file's name (without .py).

Install:  pip install pytest httpx
Run:      python -m pytest -v
"""
import importlib
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi.testclient import TestClient

APP_MODULE = "notes_api"  # the name of the module that contains the FastAPI app
TEST_SECRET = "test-secret-key-that-is-long-enough-for-hs256"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture
def app_module(tmp_path, monkeypatch):
    """Load a fresh copy of the app that uses a throwaway database.

    The app opens "notes.db" at import time, so we chdir into a temp dir and
    re-import the module. Every test starts with an empty database.
    """
    monkeypatch.setenv("JWT_SECRET", TEST_SECRET)
    monkeypatch.chdir(tmp_path)

    # TestClient runs the app in a different thread than the one importing
    # the module; sqlite refuses that by default.
    real_connect = sqlite3.connect
    monkeypatch.setattr(
        sqlite3,
        "connect",
        lambda *args, **kwargs: real_connect(*args, check_same_thread=False, **kwargs),
    )

    module = importlib.import_module(APP_MODULE)
    return importlib.reload(module)


@pytest.fixture
def client(app_module):
    return TestClient(app_module.app)


@pytest.fixture
def make_user(client):
    """Factory fixture: make_user("bob") registers, logs in, returns auth headers."""

    def _make_user(username="alice", password="password123"):
        r = client.post("/register", params={"username": username, "password": password})
        assert r.status_code == 200, r.text
        r = client.post("/login", params={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    return _make_user


@pytest.fixture
def alice(make_user):
    return make_user("alice")


@pytest.fixture
def bob(make_user):
    return make_user("bob")


def add_note(client, headers, title="Title", content="Content"):
    r = client.post(
        "/create_note",
        params={"title": title, "content": content},
        headers=headers,
    )
    assert r.status_code == 200, r.text


def get_notes(client, headers):
    r = client.get("/list_notes", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["notes"]  # each note is [id, title, content]


def make_token(sub="1", secret=TEST_SECRET, minutes=5, **extra):
    payload = {"exp": datetime.now(timezone.utc) + timedelta(minutes=minutes), **extra}
    if sub is not None:
        payload["sub"] = sub
    return jwt.encode(payload, secret, algorithm="HS256")


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------
def test_root_returns_welcome_message(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "Notes API" in r.json()["message"]


# --------------------------------------------------------------------------
# HTTP methods: state-changing endpoints must not answer to GET
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "/register?username=a&password=b",
        "/login?username=a&password=b",
        "/create_note?title=a&content=b",
        "/delete_note?note_id=1",
    ],
)
def test_state_changing_endpoints_reject_get(client, url):
    assert client.get(url).status_code == 405


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------
def test_register_new_user_succeeds(client):
    r = client.post("/register", params={"username": "alice", "password": "pw"})
    assert r.status_code == 200


def test_register_duplicate_username_returns_409(client):
    client.post("/register", params={"username": "alice", "password": "pw"})
    r = client.post("/register", params={"username": "alice", "password": "other"})
    assert r.status_code == 409


def test_register_missing_parameters_returns_422(client):
    r = client.post("/register", params={"username": "alice"})
    assert r.status_code == 422


@pytest.mark.xfail(reason="Known issue: passwords are stored in plain text")
def test_password_is_not_stored_in_plain_text(client, app_module):
    client.post("/register", params={"username": "alice", "password": "password123"})
    stored = app_module.cursor.execute(
        "SELECT password_hash FROM users WHERE username = 'alice'"
    ).fetchone()[0]
    assert stored != "password123"


# --------------------------------------------------------------------------
# Login
# --------------------------------------------------------------------------
def test_login_returns_bearer_token(client):
    client.post("/register", params={"username": "alice", "password": "pw"})
    r = client.post("/login", params={"username": "alice", "password": "pw"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_wrong_password_returns_401(client):
    client.post("/register", params={"username": "alice", "password": "pw"})
    r = client.post("/login", params={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


def test_login_unknown_user_returns_401(client):
    r = client.post("/login", params={"username": "ghost", "password": "pw"})
    assert r.status_code == 401


def test_login_error_does_not_reveal_which_part_was_wrong(client):
    """Wrong password and unknown user should look identical to an attacker."""
    client.post("/register", params={"username": "alice", "password": "pw"})
    wrong_pw = client.post("/login", params={"username": "alice", "password": "x"})
    no_user = client.post("/login", params={"username": "ghost", "password": "x"})
    assert wrong_pw.status_code == no_user.status_code
    assert wrong_pw.json() == no_user.json()


def test_token_has_string_sub_and_future_expiry(client):
    client.post("/register", params={"username": "alice", "password": "pw"})
    r = client.post("/login", params={"username": "alice", "password": "pw"})
    payload = jwt.decode(r.json()["access_token"], TEST_SECRET, algorithms=["HS256"])
    assert isinstance(payload["sub"], str)
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    assert exp > datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Authentication on protected endpoints
# --------------------------------------------------------------------------
PROTECTED = [
    ("post", "/create_note?title=a&content=b"),
    ("get", "/list_notes"),
    ("post", "/delete_note?note_id=1"),
    ("get", "/get_note_by_id/1"),
]


@pytest.mark.parametrize("method,url", PROTECTED)
def test_protected_endpoint_without_token_is_rejected(client, method, url):
    r = getattr(client, method)(url)
    # FastAPI's HTTPBearer returns 403 in older versions and 401 in newer ones
    assert r.status_code in (401, 403)


@pytest.mark.parametrize("method,url", PROTECTED)
def test_protected_endpoint_with_garbage_token_returns_401(client, method, url):
    r = getattr(client, method)(url, headers=bearer("not-a-real-token"))
    assert r.status_code == 401


def test_valid_hand_made_token_is_accepted(client):
    """Sanity check for the token helper, so the rejection tests below mean something."""
    r = client.get("/list_notes", headers=bearer(make_token(sub="1")))
    assert r.status_code == 200


def test_expired_token_returns_401(client):
    r = client.get("/list_notes", headers=bearer(make_token(minutes=-1)))
    assert r.status_code == 401


def test_token_signed_with_wrong_secret_returns_401(client):
    forged = make_token(secret="attacker-guessed-secret-key-0123456789")
    r = client.get("/list_notes", headers=bearer(forged))
    assert r.status_code == 401


def test_token_with_alg_none_returns_401(client):
    """Classic JWT attack: an unsigned token claiming alg=none."""
    unsigned = jwt.encode({"sub": "1"}, key=None, algorithm="none")
    r = client.get("/list_notes", headers=bearer(unsigned))
    assert r.status_code == 401


def test_token_without_sub_returns_401(client):
    r = client.get("/list_notes", headers=bearer(make_token(sub=None)))
    assert r.status_code == 401


def test_token_with_integer_sub_returns_401(client):
    r = client.get("/list_notes", headers=bearer(make_token(sub=1)))
    assert r.status_code == 401


# --------------------------------------------------------------------------
# Creating and listing notes
# --------------------------------------------------------------------------
def test_new_user_has_no_notes(client, alice):
    assert get_notes(client, alice) == []


def test_created_note_appears_in_list(client, alice):
    add_note(client, alice, "Shopping", "milk, eggs")
    notes = get_notes(client, alice)
    assert len(notes) == 1
    _id, title, content = notes[0]
    assert (title, content) == ("Shopping", "milk, eggs")


def test_multiple_notes_are_all_listed(client, alice):
    add_note(client, alice, "one", "1")
    add_note(client, alice, "two", "2")
    assert [n[1] for n in get_notes(client, alice)] == ["one", "two"]


def test_create_note_missing_title_returns_422(client, alice):
    r = client.post("/create_note", params={"content": "no title"}, headers=alice)
    assert r.status_code == 422


def test_note_with_sql_metacharacters_is_stored_literally(client, alice):
    """Parameterized queries mean this is just text, not SQL."""
    nasty = "'); DROP TABLE notes; --"
    add_note(client, alice, nasty, nasty)
    notes = get_notes(client, alice)
    assert notes[0][1] == nasty


# --------------------------------------------------------------------------
# Getting one note
# --------------------------------------------------------------------------
def test_get_note_by_id_returns_the_note(client, alice):
    add_note(client, alice, "Hello", "World")
    note_id = get_notes(client, alice)[0][0]

    r = client.get(f"/get_note_by_id/{note_id}", headers=alice)
    assert r.status_code == 200
    assert r.json() == {"id": note_id, "title": "Hello", "content": "World"}


def test_get_nonexistent_note_returns_404(client, alice):
    r = client.get("/get_note_by_id/9999", headers=alice)
    assert r.status_code == 404


def test_get_note_with_non_integer_id_returns_422(client, alice):
    r = client.get("/get_note_by_id/abc", headers=alice)
    assert r.status_code == 422


# --------------------------------------------------------------------------
# Deleting notes
# --------------------------------------------------------------------------
def test_delete_note_removes_it(client, alice):
    add_note(client, alice)
    note_id = get_notes(client, alice)[0][0]

    r = client.post("/delete_note", params={"note_id": note_id}, headers=alice)
    assert r.status_code == 200
    assert get_notes(client, alice) == []


def test_delete_nonexistent_note_returns_404(client, alice):
    r = client.post("/delete_note", params={"note_id": 9999}, headers=alice)
    assert r.status_code == 404


def test_delete_same_note_twice_returns_404_the_second_time(client, alice):
    add_note(client, alice)
    note_id = get_notes(client, alice)[0][0]
    client.post("/delete_note", params={"note_id": note_id}, headers=alice)
    r = client.post("/delete_note", params={"note_id": note_id}, headers=alice)
    assert r.status_code == 404


# --------------------------------------------------------------------------
# Isolation between users (the most important security tests)
# --------------------------------------------------------------------------
def test_users_only_see_their_own_notes(client, alice, bob):
    add_note(client, alice, "alice secret", "a")
    add_note(client, bob, "bob secret", "b")

    assert [n[1] for n in get_notes(client, alice)] == ["alice secret"]
    assert [n[1] for n in get_notes(client, bob)] == ["bob secret"]


def test_user_cannot_read_another_users_note(client, alice, bob):
    add_note(client, alice, "private", "stuff")
    alice_note_id = get_notes(client, alice)[0][0]

    r = client.get(f"/get_note_by_id/{alice_note_id}", headers=bob)
    assert r.status_code == 404  # 404, not 403: don't confirm the note exists


def test_user_cannot_delete_another_users_note(client, alice, bob):
    add_note(client, alice, "private", "stuff")
    alice_note_id = get_notes(client, alice)[0][0]

    r = client.post("/delete_note", params={"note_id": alice_note_id}, headers=bob)
    assert r.status_code == 404
    assert len(get_notes(client, alice)) == 1  # the note must still be there


def test_many_users_stay_isolated(client, make_user):
    """Uses the factory fixture to create several users with one line each."""
    users = {name: make_user(name) for name in ["u1", "u2", "u3"]}
    for name, headers in users.items():
        add_note(client, headers, f"note of {name}", "x")
    for name, headers in users.items():
        assert [n[1] for n in get_notes(client, headers)] == [f"note of {name}"]