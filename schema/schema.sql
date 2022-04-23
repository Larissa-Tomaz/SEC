CREATE TABLE account
(
    pubKey              VARCHAR(5000)   NOT NULL PRIMARY KEY,
    balance             REAL            NOT NULL,
    versionNumber       INTEGER         NOT NULL,
    signatureRegister   bytea   NOT NULL

);

CREATE TABLE movement
(
    movementId         INTEGER NOT NULL PRIMARY KEY,
    amount             REAL NOT NULL,
    timeStampMovement  BIGINT NOT NULL,           
    signatureMovement  bytea NOT NULL,
    sourceAccount      VARCHAR(5000) NOT NULL,
    destinationAccount VARCHAR(5000) NOT NULL,
    transferStatus     VARCHAR(100)  NOT NULL
    
);