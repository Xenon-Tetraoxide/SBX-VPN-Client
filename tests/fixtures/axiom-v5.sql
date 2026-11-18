PRAGMA user_version = 5;
CREATE TABLE profile_entries (
    id TEXT NOT NULL PRIMARY KEY,
    type TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    name TEXT NOT NULL,
    url TEXT,
    last_update TEXT NOT NULL,
    update_interval INTEGER,
    upload INTEGER,
    download INTEGER,
    total INTEGER,
    expire TEXT,
    web_page_url TEXT,
    support_url TEXT,
    populated_headers TEXT,
    profile_override TEXT,
    user_override TEXT
);
