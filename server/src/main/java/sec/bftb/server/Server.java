package sec.bftb.server;

import sec.bftb.crypto.CryptographicFunctions;

import sec.bftb.server.Logger;
import sec.bftb.server.exceptions.ErrorMessage;
import sec.bftb.server.exceptions.ServerException;

import sec.bftb.grpc.Contract.*;
import sec.bftb.grpc.BFTBankingGrpc;

import com.google.common.primitives.Bytes;
import com.google.protobuf.ByteString;

import java.io.*;
import java.security.*;
import java.sql.SQLException;
import java.util.*;


public class Server {

    public final float INITIAL_BALANCE = 50;
	public final ServerRepo serverRepo;
    private final Logger logger;
    private final int serverPort;
    private Map<String, List<Integer>> nonces = new TreeMap<>();

	public Server(int server_port) throws IOException, ServerException{

        serverRepo = new ServerRepo(server_port);
        logger = new Logger("Server", "App");
        serverPort = server_port;
    }

	public synchronized String ping() {
		return "I'm alive!";
	}

    public openAccountResponse open_account(ByteString clientPublicKey, ByteString registerSignature,int sequenceNumber, ByteString hashMessage) throws Exception{
        
        List <Integer> values = nonces.get(new String(clientPublicKey.toByteArray()));
        if(values != null && values.contains(sequenceNumber))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        
        try{
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(clientPublicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            String hashMessageString = CryptographicFunctions.decrypt(clientPublicKey.toByteArray(), hashMessage.toByteArray());

            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);
        
            
            float balance = this.serverRepo.getBalance(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));

            if (balance != -1)
                throw new ServerException(ErrorMessage.USER_ALREADY_EXISTS);
            this.serverRepo.openAccount(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()),
             INITIAL_BALANCE, new String(registerSignature.toByteArray()));

            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(String.valueOf(INITIAL_BALANCE).getBytes());
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));
        
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(clientPublicKey.toByteArray()), nonce);

            openAccountResponse response = openAccountResponse.newBuilder()
                        .setBalance(INITIAL_BALANCE).setSequenceNumber(sequenceNumber + 1)
                        .setHashMessage(encryptedHashReply).build();
            return response;
        }  
        catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new GeneralSecurityException(e); 
        }
    }
    


    public sendAmountResponse send_amount(ByteString sourcePublicKey, ByteString destinationPublicKey, float amount, int sequenceNumber, ByteString hashMessage) throws Exception{

        float balance;
        List <Integer> values = nonces.get(new String(sourcePublicKey.toByteArray()));
        if(values != null && values.contains(sequenceNumber))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        try{
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(sourcePublicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(destinationPublicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(amount).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            String hashMessageString = CryptographicFunctions.decrypt(sourcePublicKey.toByteArray(), hashMessage.toByteArray());
            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);
            
            balance = this.serverRepo.getBalance(Base64.getEncoder().encodeToString(destinationPublicKey.toByteArray()));
            if (balance == -1)
                throw new ServerException(ErrorMessage.DESTINATION_ACCOUNT_DOESNT_EXIST); 
            balance = this.serverRepo.getBalance(Base64.getEncoder().encodeToString(sourcePublicKey.toByteArray()));
            if (balance == -1)
                throw new ServerException(ErrorMessage.SOURCE_ACCOUNT_DOESNT_EXIST);
            if(balance<amount)
                throw new ServerException(ErrorMessage.NOT_ENOUGH_BALANCE);

            this.serverRepo.updateBalance(Base64.getEncoder().encodeToString(sourcePublicKey.toByteArray()), balance-amount);

            int nextId = this.serverRepo.getMaxTranferId() + 1;
            this.serverRepo.addTransfer(Base64.getEncoder().encodeToString(sourcePublicKey.toByteArray()),
            Base64.getEncoder().encodeToString(destinationPublicKey.toByteArray()), amount, nextId, "PENDING"); 

            

            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(String.valueOf(nextId).getBytes()); 
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));
        
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(sourcePublicKey.toByteArray()), nonce);

            sendAmountResponse response = sendAmountResponse.newBuilder()
                        .setTransferId(nextId).setSequenceNumber(sequenceNumber + 1)  
                        .setHashMessage(encryptedHashReply).build();
            return response;
          
        
        }catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new GeneralSecurityException(e); 
        }
    }




    public checkAccountResponse check_account(ByteString clientPublicKey, int sequenceNumber) throws Exception{
        
        try{
            //Obtain user's balance
            String clientPublicKeyString = Base64.getEncoder().encodeToString(clientPublicKey.toByteArray());
            float balance = this.serverRepo.getBalance(clientPublicKeyString);
            if (balance == -1)
                throw new ServerException(ErrorMessage.NO_SUCH_USER);
            int registerSequenceNumber = this.serverRepo.getVersionNumber(clientPublicKeyString);
            String registerSignature = this.serverRepo.getSignature(clientPublicKeyString);
           
            List<Movement> movements = this.serverRepo.getPendingMovements(clientPublicKeyString);

            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(movements.toString().getBytes());
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(balance).getBytes());
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));
        
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(clientPublicKey.toByteArray()), nonce);

            checkAccountResponse response = checkAccountResponse.newBuilder().addAllPendingMovements(movements)
                        .setBalance(balance).setRegisterSignature(ByteString.copyFrom(registerSignature.getBytes()))
                        .setRegisterSequenceNumber(registerSequenceNumber).setSequenceNumber(sequenceNumber + 1).setHashMessage(encryptedHashReply).build();
            return response;
        }  
        catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new GeneralSecurityException(e); 
        }
    }




    public receiveAmountResponse receive_amount(ByteString clientPublicKey,int transferID, int sequenceNumber, ByteString hashMessage) throws Exception{
        
        List <Integer> values = nonces.get(new String(clientPublicKey.toByteArray()));
        if(values != null && values.contains(sequenceNumber))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        
        try{
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(clientPublicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(transferID).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            String hashMessageString = CryptographicFunctions.decrypt(clientPublicKey.toByteArray(), hashMessage.toByteArray());

            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);


            //Checks if user exists and obtains his balance
            float receiverBalance = this.serverRepo.getBalance(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            if (receiverBalance == -1)
                throw new ServerException(ErrorMessage.NO_SUCH_USER);

            String destinationUser = this.serverRepo.getDestinationUser(transferID);
            if(!destinationUser.equals(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()))){
                throw new ServerException(ErrorMessage.INVALID_RECEIVER);
            }
            
            String status = this.serverRepo.getTransferStatus(transferID);
            if(!status.equals("PENDING")){
                throw new ServerException(ErrorMessage.INVALID_STATUS);
            }

            

            int flag = this.serverRepo.receiveAmount(transferID, "APPROVED", receiverBalance);
            if(flag == -1)
                throw new ServerException(ErrorMessage.NO_SUCH_TRANSFER);
            
            

            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));
        
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(clientPublicKey.toByteArray()), nonce);

            receiveAmountResponse response = receiveAmountResponse.newBuilder().setSequenceNumber(sequenceNumber + 1)
                        .setHashMessage(encryptedHashReply).build();
            return response;
        }  
        catch(GeneralSecurityException e){
            throw new GeneralSecurityException(e); 
        }
    }


    public auditResponse audit(ByteString clientPublicKey, int sequenceNumber, ByteString hashMessage) throws Exception{
    
        List <Integer> values = nonces.get(new String(clientPublicKey.toByteArray()));
        if(values != null && values.contains(sequenceNumber))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        
        try{
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(clientPublicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            String hashMessageString = CryptographicFunctions.decrypt(clientPublicKey.toByteArray(), hashMessage.toByteArray());

            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);
        
            float balance = this.serverRepo.getBalance(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            if (balance == -1)
                throw new ServerException(ErrorMessage.USER_ALREADY_EXISTS);

            List<Movement> movements = this.serverRepo.getCompletedMovements(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            
           
            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(movements.toString().getBytes());
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));
        
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(clientPublicKey.toByteArray()), nonce);

            auditResponse response = auditResponse.newBuilder().addAllConfirmedMovements(movements)
                        .setSequenceNumber(sequenceNumber + 1).setHashMessage(encryptedHashReply).build();
            return response;
        }  
        catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new GeneralSecurityException(e); 
        }
    }

    public highestRegisterSequenceNumberResponse getHighestSeq() throws Exception{
        try{
            highestRegisterSequenceNumberResponse response = highestRegisterSequenceNumberResponse.newBuilder().build();
            return response;
        }  
        catch(Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new Exception(e); 
        }
    }

    public writeBackResponse writeBack() throws Exception{
        try{
            writeBackResponse response = writeBackResponse.newBuilder().build();
            return response;
        }  
        catch(Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new Exception(e); 
        }
    }
}