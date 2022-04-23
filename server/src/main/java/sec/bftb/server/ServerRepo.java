package sec.bftb.server;

import org.apache.ibatis.jdbc.ScriptRunner;

import sec.bftb.grpc.Contract.*;
import sec.bftb.server.exceptions.ErrorMessage;
import sec.bftb.server.exceptions.ServerException;
import sec.bftb.grpc.BFTBankingGrpc;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigDecimal;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;

import com.google.protobuf.ByteString;

public class ServerRepo {

    private final Logger logger;
    private Properties props;
    /*private final String dbUrl;
    private final String dbUsername;
    private final String dbPassword;
    private final String dbDir;*/

    private Connection connection = null;
    private PreparedStatement statement = null;
    private ResultSet resultSet = null;

    public ServerRepo(int serverId, boolean clearDB) throws ServerException {
        this.logger = new Logger("Server", "SQL");

        Properties prop = new Properties();
        String databaseUrl = "";
        try (var file = new FileInputStream("resources/database.properties")) {
            prop.load(file);

            //Set correct url for this replica
            databaseUrl = prop.getProperty("url").substring(0, prop.getProperty("url").length() - 8) + "bftb_db" + serverId;

            //Create server database if it does not exist
            try (Connection connection = DriverManager.getConnection(prop.getProperty("url"), prop);
                 Statement stmt = connection.createStatement()) {
                stmt.execute("CREATE DATABASE bftb_db" + serverId);
                logger.log("Database created!");

                try (Connection con = DriverManager.getConnection(databaseUrl, prop)) {
                    ScriptRunner scriptRunner = new ScriptRunner(con);
                    scriptRunner.setLogWriter(null);
                    scriptRunner.runScript(new BufferedReader(new FileReader("../schema/schema.sql")));
                   
                } catch (Exception e) {
                    logger.log(e.getMessage());
                }
            }
        } catch (FileNotFoundException e) {
            logger.log("Database properties file not found.");
            throw new ServerException(ErrorMessage.FAILED_DB_CONNECTION);
        } catch (IOException e) {
            logger.log("IO error reading the database properties file.");
            throw new ServerException(ErrorMessage.FAILED_DB_CONNECTION);
        } catch (SQLException ignored) {
        }
        prop.setProperty("url", databaseUrl);
        this.props = prop;
    }

    private Connection newConnection() throws SQLException {
        return DriverManager.getConnection(this.props.getProperty("url"), this.props);
    }

    /*private void closeConnection(){
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException e) { 
                this.logger.log(e.getMessage());
            }
        }

        if (statement != null) {
            try {
                statement.close();
            } catch (SQLException e) {
                this.logger.log(e.getMessage());
            }
        }

        if (resultSet != null) {
            try {
                resultSet.close();
            } catch (SQLException e) {
                this.logger.log(e.getMessage());
            }
        }
    }*/

    public void openAccount(String pubKey, Float balance, byte[] signatureRegister) throws SQLException {
        try {
            String query = "INSERT INTO account (pubKey, balance, versionNumber, signatureRegister) VALUES (?, ?, ?, ?)";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setString(1, pubKey);
            statement.setFloat(2, balance);
            statement.setInt(3, 0);
            statement.setBytes(4, signatureRegister);
            statement.executeUpdate();
        } finally {
            //closeConnection();
        }
    }

    public int getTransferId(int id) throws SQLException {
        try {
            String query = "SELECT transferStatus FROM movement WHERE movementId=?";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setInt(1, id);

            resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return id;             
            }
            else{
                return -1;
            }
        } finally{
            //closeConnection();
        }
    }


    public String getTransferStatus(int id) throws SQLException {
        try {
            String query = "SELECT transferStatus FROM movement WHERE movementId=?";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setInt(1, id);

            resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString("transferStatus");             
            }
            else{
                return "-1";
            }
        } finally{
            //closeConnection();
        }
    }

    public String getDestinationUser(int id) throws SQLException {
        try {
            String query = "SELECT destinationAccount FROM movement WHERE movementId=?";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setInt(1, id);

            resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString("destinationAccount");             
            }
            else{
                return "-1";
            }
        } finally{
            //closeConnection();
        }
    }


    public Movement getMovement(int transferID) throws SQLException{
        try{ 
            String query = "SELECT movementId,amount,timeStampMovement,signatureMovement,sourceAccount,destinationAccount,transferStatus FROM movement WHERE movementId = ? and transferStatus = 'PENDING'";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setInt(1, transferID);

            resultSet = statement.executeQuery();
            if (resultSet.next()) {         
            
                String source = resultSet.getString("sourceAccount");
                String destination = resultSet.getString("destinationAccount");
                String status = resultSet.getString("transferStatus");
                long timeStamp = resultSet.getBigDecimal("timeStampMovement").longValue();
                byte[] signature = resultSet.getBytes("signatureMovement");
                int transferId = resultSet.getInt("movementId");      
                float amount = resultSet.getFloat("amount");

                Movement mov = Movement.newBuilder().setMovementID(transferId).setMovementSignature(ByteString.copyFrom(signature)).setTimeStamp(timeStamp)
                .setSignatureKey(ByteString.copyFrom(Base64.getDecoder().decode(source))).setAmount(amount).setStatus(status).build();
                
                return mov;
            }
            else{
                return Movement.newBuilder().build();
            }
            
        } finally {
            //closeConnection();
        }

    }

    public List<Movement> getPendingMovements(String pubKey) throws SQLException{
        try{ 
            String query = "SELECT movementId,amount,timeStampMovement,signatureMovement,sourceAccount,destinationAccount,transferStatus FROM movement WHERE destinationAccount = ? and transferStatus = 'PENDING'";
            ArrayList<Movement> movements = new ArrayList<>();
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setString(1, pubKey);

            resultSet = statement.executeQuery();
            while(resultSet.next()){
                String source = resultSet.getString("sourceAccount");
                String destination = resultSet.getString("destinationAccount");
                String status = resultSet.getString("transferStatus");
                long timeStamp = resultSet.getBigDecimal("timeStampMovement").longValue();
                byte[] signature = resultSet.getBytes("signatureMovement");
                int transferId = resultSet.getInt("movementId");      
                float amount = resultSet.getFloat("amount");

                Movement mov = Movement.newBuilder().setMovementID(transferId).setTimeStamp(timeStamp)
                .setMovementSignature(ByteString.copyFrom(signature)).setSignatureKey(ByteString.copyFrom(Base64.getDecoder()
                .decode(source))).setAmount(amount).setStatus(status).build();

                movements.add(mov);
            }
            return movements;

        } finally {
            //closeConnection();
        }
    }


    public List<Movement> getCompletedMovements(String pubKey) throws SQLException{
        try{ 
            String query = "SELECT movementId,amount,timeStampMovement,signatureMovement,sourceAccount,destinationAccount,transferStatus FROM movement WHERE destinationAccount = ? and transferStatus = 'APPROVED'";
            String query2 = "SELECT movementId,amount,timeStampMovement,signatureMovement,sourceAccount,destinationAccount,transferStatus FROM movement WHERE sourceAccount = ? and transferStatus = 'APPROVED'";

            ArrayList<Movement> movements = new ArrayList<>();
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setString(1, pubKey);

            resultSet = statement.executeQuery();
            while(resultSet.next()){
                String source = resultSet.getString("sourceAccount");
                String destination = resultSet.getString("destinationAccount");
                String status = resultSet.getString("transferStatus");
                long timeStamp = resultSet.getBigDecimal("timeStampMovement").longValue();
                byte[] signature = resultSet.getBytes("signatureMovement");
                int transferId = resultSet.getInt("movementId");      
                float amount = resultSet.getFloat("amount");

                Movement mov = Movement.newBuilder().setMovementID(transferId).setAmount(amount).setTimeStamp(timeStamp)
                .setMovementSignature(ByteString.copyFrom(signature)).setSignatureKey(ByteString.copyFrom(Base64.getDecoder()
                .decode(destination))).setStatus(status).setDirectionOfTransfer("Received").build();

                movements.add(mov);
            }

            statement = connection.prepareStatement(query2);
            statement.setString(1, pubKey);

            resultSet = statement.executeQuery();
            while(resultSet.next()){
                String source = resultSet.getString("sourceAccount");
                String destination = resultSet.getString("destinationAccount");
                String status = resultSet.getString("transferStatus");
                long timeStamp = resultSet.getBigDecimal("timeStampMovement").longValue();
                byte[] signature = resultSet.getBytes("signatureMovement");
                int transferId = resultSet.getInt("movementId");      
                float amount = resultSet.getFloat("amount");

                Movement mov = Movement.newBuilder().setMovementID(transferId).setAmount(amount).setTimeStamp(timeStamp)
                .setMovementSignature(ByteString.copyFrom(signature)).setSignatureKey(ByteString.copyFrom(Base64.getDecoder().decode(destination)))
                .setStatus(status).setDirectionOfTransfer("Sent").build();

                movements.add(mov);
            }

            return movements;

        } finally {
            //closeConnection();
        }
    }
    


    public void addTransfer(String srcPubKey, String destPubKey, Float amount, int movementId, String transferStatus, long timeStamp,byte[] movementSignature) throws SQLException {
        try {
            String query = "INSERT INTO movement (movementId, amount, timeStampMovement, signatureMovement, sourceAccount, destinationAccount, transferStatus) VALUES (?, ?, ?, ?, ?, ?, ?)";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setInt(1, movementId);
            statement.setFloat(2, amount);
            statement.setBigDecimal(3, new BigDecimal(timeStamp));
            statement.setBytes(4, movementSignature);
            statement.setString(5, srcPubKey);
            statement.setString(6, destPubKey);
            statement.setString(7, transferStatus);
            statement.executeUpdate();
        } finally {
            //closeConnection();
        }
    }

    public int receiveAmount(int id, String newStatus, byte[] signatureMovement, long timeStamp) throws SQLException { //Change function to insert new row instead of updating
        try {
            String query = "UPDATE movement SET transferStatus=? WHERE movementId=?";   
            String query2 = "UPDATE movement SET signatureMovement=? WHERE movementId=?";
            String query3 = "UPDATE movement SET timeStampMovement=? WHERE movementId=?";

            connection = this.newConnection();

            statement = connection.prepareStatement(query);
            statement.setString(1, newStatus);
            statement.setInt(2, id);
            statement.executeUpdate();

            statement = connection.prepareStatement(query2);
            statement.setBytes(1, signatureMovement);
            statement.setInt(2, id);
            statement.executeUpdate();

            statement = connection.prepareStatement(query3);
            statement.setBigDecimal(1, new BigDecimal(timeStamp));
            statement.setInt(2, id);
            statement.executeUpdate();
            return 0;

        } finally {
            //closeConnection();
        }
    }

    public float getBalance(String pubKey) throws SQLException {
        try {
            String query = "SELECT balance FROM account WHERE pubKey=?";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setString(1, pubKey);

            resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getFloat("balance");             
            }
            else{
                return -1; 
            }
        } finally{
            //closeConnection();
        }
    }

    public void updateBalance(String pubKey, float newBalance) throws SQLException {
        try {
            String query = "UPDATE account SET balance=? WHERE pubKey=?";

            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setFloat(1, newBalance);
            statement.setString(2, pubKey);
            statement.executeUpdate();
        } finally {
            //closeConnection();
        }
    }


    public int getVersionNumber(String pubKey) throws SQLException {
        try {
            String query = "SELECT versionNumber FROM account WHERE pubKey=?";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setString(1, pubKey);

            resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("versionNumber");             
            }
            else{
                return -1; 
            }
        } finally{
            //closeConnection();
        }
    }

    public void updateVersionNumber(String pubKey, int newVersionNumber) throws SQLException {
        try {
            String query = "UPDATE account SET versionNumber=? WHERE pubKey=?";

            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setInt(1, newVersionNumber);
            statement.setString(2, pubKey);
            statement.executeUpdate();
        } finally {
            //closeConnection();
        }
    }


    public byte[] getSignature(String pubKey) throws SQLException {
        try {
            String query = "SELECT signatureRegister FROM account WHERE pubKey=?";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setString(1, pubKey);

            resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getBytes("signatureRegister");             
            }
            else{
                return new byte[-1]; 
            }
        } finally{
            //closeConnection();
        }
    }

    public void updateSignature(String pubKey, byte[] newSignature) throws SQLException {
        try {
            String query = "UPDATE account SET signatureRegister=? WHERE pubKey=?";

            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            statement.setBytes(1, newSignature);
            statement.setString(2, pubKey);
            statement.executeUpdate();
        } finally {
            //closeConnection();
        }
    }


    public int getMaxTranferId() throws SQLException {
        try {
            String query = "SELECT MAX(movementId) AS maxId FROM movement";
            connection = this.newConnection();
            statement = connection.prepareStatement(query);
            resultSet = statement.executeQuery();

            if (resultSet.next())
                return resultSet.getInt("maxId");
            else
                return -1;
    
        } finally {
            //closeConnection();
        }
    }
}