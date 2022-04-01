package sec.bftb.client;

import java.sql.Timestamp;
import java.time.Instant;

public class Logger {

    private final String type;
    private final String subType;

    public Logger(String type, String subType) {
        this.type = type;
        this.subType = subType;
    }

    public void log(String message) {
        String logMessage = String.format("[%s][%s][%s] %s",
                Timestamp.from(Instant.now()),
                this.type,
                this.subType,
                message);

        System.out.println(logMessage);
    }
}