CREATE TABLE Control (
    dbVersion   TEXT NOT NULL,
    appVersion  TEXT,
    accountName TEXT
);

CREATE TABLE RasAccess (
    accountId TEXT,
    deviceId  TEXT,
    ipAddress TEXT NOT NULL
);

CREATE TABLE RasAccessError (
    ipAddress TEXT     NOT NULL,
    timestamp DATETIME NOT NULL,
    reason    TEXT
);

CREATE TABLE RasFilter (
    accountId TEXT,
    ruleName  TEXT,
    groupName TEXT,
	unloaded  BOOLEAN DEFAULT (0),
	forced    BOOLEAN DEFAULT (0)
);

CREATE TABLE RasRestore (
	restoreKey      TEXT     NOT NULL PRIMARY KEY,
    ruleName        TEXT,
    groupName       TEXT,
	applicationName TEXT,
	serviceName     TEXT,
	profiles        INTEGER,
	protocol        INTEGER,
	direction       INTEGER,
	localPorts      TEXT,
	localAddresses  TEXT,
	remotePorts     TEXT,
	remoteAddresses TEXT,
	action          INTEGER,
	enabled         BOOLEAN,
	removeable      BOOLEAN  DEFAULT (0),
	ignored         BOOLEAN  DEFAULT (0),
	unloaded        BOOLEAN  DEFAULT (0)
);


CREATE UNIQUE INDEX IX_RasAccess_unique ON RasAccess (
    ifnull(accountId, '<null>'),
    ifnull(deviceId, '<null>')
);

CREATE INDEX IX_RasAccessError_primary ON RasAccessError (
    ipAddress,
    timestamp
);

CREATE UNIQUE INDEX IX_RasFilter_unique ON RasFilter (
    ifnull(accountId, '<null>'),
    ifnull(ruleName, '<null>'),
    ifnull(groupName, '<null>')
);

CREATE INDEX IX_RasFilter_groupName ON RasFilter (
    groupName
);

CREATE INDEX IX_RasFilter_ruleName ON RasFilter (
    ruleName
);


INSERT INTO Control (dbVersion) VALUES (1);

INSERT INTO RasAccess (accountId, ipAddress)
VALUES ('<sentinel>', '1.1.1.1');
