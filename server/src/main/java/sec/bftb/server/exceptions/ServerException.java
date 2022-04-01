package sec.bftb.server.exceptions;

import sec.bftb.server.Logger;

public class ServerException extends Exception {
    private final String message;
    private final Logger logger;

    public ServerException(ErrorMessage errorMessage) {
        this.message = errorMessage.toString();
        this.logger = new Logger("Server", "Exception");
        this.logger.log(message);
    }

    public String getMessage() {
        return this.message;
    }
}
