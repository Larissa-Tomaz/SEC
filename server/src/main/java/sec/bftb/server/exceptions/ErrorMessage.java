package sec.bftb.server.exceptions;

public enum ErrorMessage {
    
    MESSAGE_INTEGRITY("Message integrity compromissed."),
    SEQUENCE_NUMBER("Invalid Sequence Number, possible replay attack detected."),
    USER_ALREADY_EXISTS("This user already has an account"),
    NO_SUCH_USER("User was not found"),
    SOURCE_ACCOUNT_DOESNT_EXIST("The source account does not exist"),
    DESTINATION_ACCOUNT_DOESNT_EXIST("The destination account does not exist"),
    NOT_ENOUGH_BALANCE("The account balance is not sufficient "),
    NO_SUCH_TRANSFER("Transfer not found"),
    INVALID_STATUS("Transfer already accepted"),
    INVALID_RECEIVER("User is not the right receiver of the transfer"),
    BYZANTINE_CLIENT_OR_MAX_SERVER_FAILURES("Byzantine client sent more than F different requests or more than F servers are unresponsive"),
    INVALID_KEY_PAIR("Invalid key pair"),
    FAILED_DB_CONNECTION("Failed to establish connection to database"),
    FAILED_TO_CLEAN_DB("Failed to clean database");

    
    public final String label;

    ErrorMessage(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return this.label;
    }
}
