from datetime import datetime, timedelta, timezone
import sqlite3
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
import os


# Secret key for JWT
JWT_SECRET = os.environ["JWT_SECRET"] # get the secret key from the environment variable set it with : export JWT_SECRET=your_secret_key
JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME_MINUTES = 30
bearer_scheme = HTTPBearer()

# Create a connection to the SQLite database    
DB_PATH = os.environ.get("DB_PATH", "notes.db")
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )
""")
cursor.execute('''
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
''')
conn.commit()


# Create connection to the fastapi app
app = FastAPI()


def current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> int:
    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = payload.get("sub")
    if not isinstance(user_id, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has no valid user.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id

# Define a root endpoint
@app.get("/")
async def read_root():  
    return {"message": "Welcome to the Notes API!"}

# Define endpoints 
@app.post("/register")
async def register(username: str, password: str):  # register a new user
    cursor.execute(
        "SELECT 1 FROM users WHERE username = ?",
        (username,),
    )
    if cursor.fetchone():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists.")

    cursor.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password),
    )
    conn.commit()
    return {"message": "User registered successfully."}

@app.post("/login") # return a token for the user
async def login(username: str, password: str):  
    cursor.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (username,),
    )
    user = cursor.fetchone()
    if not user or password != user[1]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
    token = jwt.encode(
        {"sub": str(user[0]), "exp": expires_at},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/create_note") # create a note for the user
async def create_note(title: str, content: str, user_id: int = Depends(current_user_id)):
    cursor.execute(
        "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
        (user_id, title, content),
    )
    conn.commit()
    return {"message": "Note created successfully."}

@app.get("/list_notes") # list all notes for the user
async def list_notes(user_id: int = Depends(current_user_id)):
    cursor.execute(
        "SELECT id, title, content FROM notes WHERE user_id = ?",
        (user_id,),
    )
    return {"notes": cursor.fetchall()}

@app.post("/delete_note") # delete a note for the user
async def delete_note(note_id: int, user_id: int = Depends(current_user_id)):
    cursor.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?",
        (note_id, user_id),
    )
    conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")
    return {"message": "Note deleted successfully."}

@app.get("/get_note_by_id/{id}") # get a note for the user
async def get_note_by_id(id: int, user_id: int = Depends(current_user_id)):
    cursor.execute(
        """SELECT id, title, content FROM notes
           WHERE id = ? AND user_id = ?""",
        (id, user_id),
    )
    note = cursor.fetchone()
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")
    return {"id": note[0], "title": note[1], "content": note[2]}
