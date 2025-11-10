import sqlite3

def create_database(db_path="database.db"):
    """
    Creates a new SQLite database using the schema defined in the DBML specification.
    All relationships and constraints are included where supported by SQLite.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    # === USERS ===
    cursor.execute("""
    CREATE TABLE Users (
        username TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        tag TEXT
    );
    """)

    # === VIDEOS ===
    cursor.execute("""
    CREATE TABLE Videos (
        vidID INTEGER PRIMARY KEY AUTOINCREMENT,
        vidType TEXT,
        game TEXT,
        mmr INTEGER,
        map TEXT,
        mode TEXT
    );
    """)

    # === MESSAGES ===
    cursor.execute("""
    CREATE TABLE Messages (
        msgID INTEGER PRIMARY KEY AUTOINCREMENT,
        boardID INTEGER,
        username TEXT NOT NULL,
        datetime TEXT,
        FOREIGN KEY (username) REFERENCES Users(username) ON DELETE CASCADE
        FOREIGN KEY (boardID) REFERENCES Forums(boardID) ON DELETE CASCADE
    );
    """)

    # === REPORTS ===
    cursor.execute("""
    CREATE TABLE Reports (
        reportID INTEGER PRIMARY KEY AUTOINCREMENT,
        msgID INTEGER NOT NULL,
        FOREIGN KEY (msgID) REFERENCES Messages(msgID) ON DELETE CASCADE
    );
    """)

    # === ARTICLES ===
    cursor.execute("""
    CREATE TABLE Articles (
        articleID INTEGER PRIMARY KEY AUTOINCREMENT,
        note TEXT
    );
    """)

    # === FORUMS ===
    cursor.execute("""
    CREATE TABLE Forums (
        forumID INTEGER PRIMARY KEY AUTOINCREMENT,
        originalPoster TEXT,
    );
    """)

    # === POSTS ===
    cursor.execute("""
    CREATE TABLE Posts (
        postID INTEGER PRIMARY KEY AUTOINCREMENT,
        tags JSON,  -- store post tags as JSON
        date TEXT
    );
    """)

    # === RELATIONSHIPS ===
    # Messages.boardID → Posts.postID
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_messages_boardID ON Messages(boardID);
    """)

    conn.commit()
    conn.close()
    print("Database created successfully.")
