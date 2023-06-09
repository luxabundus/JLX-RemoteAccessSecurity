CREATE TABLE Control (
    dbVersion   TEXT NOT NULL,
    appVersion  TEXT,
    accountName TEXT
);

CREATE TABLE RasAccessError (
    ipAddress TEXT     NOT NULL,
    timestamp DATETIME NOT NULL,
    reason    TEXT
);

CREATE INDEX IX_RasAccessError_primary ON RasAccessError (
    ipAddress,
    timestamp
);

INSERT INTO Control (dbVersion) VALUES (1);

