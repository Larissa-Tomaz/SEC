package pt.tecnico.sec.hdlt.crypto.exceptions;

import pt.tecnico.sec.hdlt.crypto.Logger;

public class CryptoException extends Exception {
    private final String message;
    private final Logger logger;

    public CryptoException(String message) {
        this.message = message;
        this.logger = new Logger("Crypto", "Exception");
        this.logger.log(message);
    }

    public String getMessage() {
        return this.message;
    }
}
