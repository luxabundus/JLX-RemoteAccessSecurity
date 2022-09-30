CREATE TABLE Control (
    dbVersion   TEXT NOT NULL,
    appVersion  TEXT
);


CREATE TABLE RasAccount (
    accountId        UNIQUEIDENTIFIER PRIMARY KEY
                                      UNIQUE
                                      NOT NULL,
    accountName      TEXT             NOT NULL
                                      UNIQUE,
	firstName        TEXT,
	lastName         TEXT,
	email            TEXT,
    password         TEXT,
    recoveryQuestion TEXT,
    recoveryAnswer   TEXT,
    creationTime     DATETIME         NOT NULL,
    accountStatus    TEXT             NOT NULL,
    maxRegistrations INTEGER          DEFAULT (1) 
);


CREATE TABLE RasRegistration (
    accountId           UNIQUEIDENTIFIER UNIQUE
                                         NOT NULL,
    registrationId      UNIQUEIDENTIFIER PRIMARY KEY
                                         NOT NULL
                                         UNIQUE,
    registrationKey     TEXT             NOT NULL,
    registrationVersion TEXT             NOT NULL,
    registrationTime    DATETIME         NOT NULL,
    registrationStatus  TEXT             NOT NULL,
	deviceName          TEXT             NOT NULL,
	ipAddress           TEXT             NOT NULL
);


CREATE UNIQUE INDEX IX_RasAccount_accountName ON RasAccount (
    accountName
);


CREATE INDEX IX_RasRegistration_accountId ON RasRegistration (
    accountId
);


CREATE INDEX IX_RasRegistration_registrationKey ON RasRegistration (
    accountId,
    registrationKey
);


INSERT INTO Control (dbVersion) VALUES (0);
