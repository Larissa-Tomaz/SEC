DROP TABLE IF EXISTS account;
DROP TABLE IF EXISTS movement;
CREATE TABLE account
(
    pubKey    VARCHAR(5000) NOT NULL PRIMARY KEY,
    balance   REAL          NOT NULL
);

CREATE TABLE movement
(
    movementId         INTEGER NOT NULL PRIMARY KEY,
    amount             REAL NOT NULL,
    sourceAccount      VARCHAR(5000) NOT NULL,
    destinationAccount VARCHAR(5000) NOT NULL,
    transferStatus     VARCHAR(100)  NOT NULL
);