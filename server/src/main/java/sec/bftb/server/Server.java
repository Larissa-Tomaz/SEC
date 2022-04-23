package sec.bftb.server;

import sec.bftb.crypto.CryptographicFunctions;

import sec.bftb.server.Logger;
import sec.bftb.server.exceptions.ErrorMessage;
import sec.bftb.server.exceptions.ServerException;

import sec.bftb.grpc.Contract.*;
import sec.bftb.grpc.BFTBankingGrpc;

import com.google.common.primitives.Bytes;
import com.google.protobuf.ByteString;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.stub.StreamObserver;

import java.io.*;
import java.security.*;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.*;

import javax.sql.rowset.serial.SerialException;


public class Server {

    public final float INITIAL_BALANCE = 50;
	public final ServerRepo serverRepo;
    private final Logger logger;
    private final int serverPort, basePort;
    private final int maxByzantineFaults, numberOfServers, byzantineQuorum;
    private final boolean isByzantine;

    private AtomicInteger uncommitedTransferID = new AtomicInteger(0);
    private Map<String, List<Integer>> nonces = new TreeMap<>();
    private ConcurrentHashMap<String,Integer> echos = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String,Integer> readies = new ConcurrentHashMap<>();

	
    public Server(int base_port, int server_port, int max_Byzantine_Faults, boolean is_Byzantine, boolean clear_DB) throws IOException, ServerException{
        serverRepo = new ServerRepo(server_port, clear_DB);
        logger = new Logger("Server", "App");
        serverPort = server_port;
        basePort = base_port;
        maxByzantineFaults = max_Byzantine_Faults;
        numberOfServers = (3 * max_Byzantine_Faults) + 1;
        byzantineQuorum = (2 * max_Byzantine_Faults) + 1;
        isByzantine = is_Byzantine;
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
             INITIAL_BALANCE, registerSignature.toByteArray());

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
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
    }
    


    public sendAmountResponse prepare_send_amount(ByteString sourcePublicKey, ByteString destinationPublicKey, float amount, int sequenceNumber, ByteString hashMessage) throws Exception{

        boolean isValidated = false;
        float balance, balanceUpdated;
        int registerSequenceNumber;
        byte[] registerSignature;

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
            messageBytes.write(Boolean.toString(isValidated).getBytes());
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

            int nextId = this.serverRepo.getMaxTranferId() + 1;
            
            if(nextId <= uncommitedTransferID.get()){ //To make sure two not committed transfers yet don't get the same transfer id
                uncommitedTransferID.getAndIncrement();
                nextId = uncommitedTransferID.get();
            }
            else
                uncommitedTransferID.set(nextId);

            registerSequenceNumber = this.serverRepo.getVersionNumber(Base64.getEncoder().encodeToString(sourcePublicKey.toByteArray()));
            registerSignature = this.serverRepo.getSignature(Base64.getEncoder().encodeToString(sourcePublicKey.toByteArray()));
            balanceUpdated = balance - amount;
             
            
            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(String.valueOf(nextId).getBytes()); 
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(balanceUpdated).getBytes()); 
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));

            if(isByzantine){
                balanceUpdated = balanceUpdated + 1000;
            }
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(sourcePublicKey.toByteArray()), nonce);

            sendAmountResponse response = sendAmountResponse.newBuilder().setTransferId(nextId).setNewBalance(balanceUpdated).setOldBalance(balance)
            .setRegisterSequenceNumber(registerSequenceNumber).setRegisterSignature(ByteString.copyFrom(registerSignature))
            .setSequenceNumber(sequenceNumber + 1).setHashMessage(encryptedHashReply).build();
            return response;
          
        
        }catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
    }



    public sendAmountResponse send_amount(sendAmountRequest request) throws Exception{
        
        boolean isValidated = true;
        float balance, balanceUpdated;
        int registerSequenceNumber;
        byte[] registerSignature;
        byte[] sourcePublicKey = request.getPublicKeySender().toByteArray();

        List <Integer> values = nonces.get(new String(sourcePublicKey));
        if(values != null && values.contains(request.getSequenceNumber()))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        try{

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(sourcePublicKey);
            messageBytes.write(":".getBytes());
            messageBytes.write(request.getPublicKeyReceiver().toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getAmount()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getTransferId()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getTimeStamp()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(request.getMovementSignature().toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getNewBalance()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getRegisterSequenceNumber()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(request.getRegisterSignature().toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getSequenceNumber()).getBytes());

            
            String hashMessageString = CryptographicFunctions.decrypt(sourcePublicKey, request.getHashMessage().toByteArray());
            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);

            doubleEcho(CryptographicFunctions.hashString(new String(messageBytes.toByteArray())));
            
            this.serverRepo.updateBalance(Base64.getEncoder().encodeToString(sourcePublicKey), request.getNewBalance());
            this.serverRepo.updateVersionNumber(Base64.getEncoder().encodeToString(sourcePublicKey), request.getRegisterSequenceNumber());
            this.serverRepo.updateSignature(Base64.getEncoder().encodeToString(sourcePublicKey), request.getRegisterSignature().toByteArray());

            this.serverRepo.addTransfer(Base64.getEncoder().encodeToString(sourcePublicKey), 
                Base64.getEncoder().encodeToString(request.getPublicKeyReceiver().toByteArray()),
                request.getAmount(), request.getTransferId(), "PENDING", request.getTimeStamp(),request.getMovementSignature().toByteArray()); 


        }catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
        
        return sendAmountResponse.newBuilder().build();
    }



    public checkAccountResponse check_account(ByteString clientPublicKey, int sequenceNumber) throws Exception{
        
        try{
            //Obtain user's balance
            String clientPublicKeyString = Base64.getEncoder().encodeToString(clientPublicKey.toByteArray());
            float balance = this.serverRepo.getBalance(clientPublicKeyString);
            if (balance == -1)
                throw new ServerException(ErrorMessage.NO_SUCH_USER);
            int registerSequenceNumber = this.serverRepo.getVersionNumber(clientPublicKeyString);
            byte[] registerSignature = this.serverRepo.getSignature(clientPublicKeyString);
           
            List<Movement> movements = this.serverRepo.getPendingMovements(clientPublicKeyString);

            if(isByzantine){
                balance = balance + 33;
                registerSequenceNumber = registerSequenceNumber + 10;
            }

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
                        .setBalance(balance).setRegisterSignature(ByteString.copyFrom(registerSignature))
                        .setRegisterSequenceNumber(registerSequenceNumber).setSequenceNumber(sequenceNumber + 1).setHashMessage(encryptedHashReply).build();
            return response;
        }  
        catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
    }




    public receiveAmountResponse prepare_receive_amount(ByteString clientPublicKey,int transferID, int sequenceNumber, ByteString hashMessage) throws Exception{
        
        boolean isValidated = false;
        int registerSequenceNumber;
        float balanceUpdated;
        byte[] registerSignature;

        List<Integer> values = nonces.get(new String(clientPublicKey.toByteArray()));
        if(values != null && values.contains(sequenceNumber))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        
        try{
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(clientPublicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(transferID).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            String hashMessageString = CryptographicFunctions.decrypt(clientPublicKey.toByteArray(), hashMessage.toByteArray());

            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);


            //Checks if user exists and obtains his balance
            float receiverBalance = this.serverRepo.getBalance(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            if (receiverBalance == -1)
                throw new ServerException(ErrorMessage.NO_SUCH_USER);
            registerSequenceNumber = this.serverRepo.getVersionNumber(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            registerSignature = this.serverRepo.getSignature(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));

            
            if(this.serverRepo.getTransferId(transferID) == -1){
                throw new ServerException(ErrorMessage.NO_SUCH_TRANSFER);
            }

            String destinationUser = this.serverRepo.getDestinationUser(transferID);
            if(!destinationUser.equals(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()))){
                throw new ServerException(ErrorMessage.INVALID_RECEIVER);
            }
            
            String status = this.serverRepo.getTransferStatus(transferID);
            if(!status.equals("PENDING")){
                throw new ServerException(ErrorMessage.INVALID_STATUS);
            }

            
            Movement mov = this.serverRepo.getMovement(transferID);
            balanceUpdated = receiverBalance + mov.getAmount();


            //int flag = this.serverRepo.receiveAmount(transferID, "APPROVED", receiverBalance);
            //if(flag == -1)
              //  throw new ServerException(ErrorMessage.NO_SUCH_TRANSFER);

            if(isByzantine){
                sequenceNumber = sequenceNumber + 5;
            }
            
            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(String.valueOf(mov).getBytes()); 
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(balanceUpdated).getBytes()); 
            replyBytes.write(":".getBytes());
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));
        
    
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(clientPublicKey.toByteArray()), nonce);

            receiveAmountResponse response = receiveAmountResponse.newBuilder().setMovement(mov).setNewBalance(balanceUpdated)
            .setOldBalance(receiverBalance).setRegisterSequenceNumber(registerSequenceNumber)
            .setRegisterSignature(ByteString.copyFrom(registerSignature))
            .setSequenceNumber(sequenceNumber + 1).setHashMessage(encryptedHashReply).build();
            return response;
        }  
        catch(GeneralSecurityException e){
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
    }


    public receiveAmountResponse receive_amount(receiveAmountRequest request) throws Exception{
        
        boolean isValidated = true;
        float balance, balanceUpdated;
        int registerSequenceNumber;
        byte[] registerSignature;
        byte[] clientPublicKey = request.getPublicKeyClient().toByteArray();

        List <Integer> values = nonces.get(new String(clientPublicKey));
        if(values != null && values.contains(request.getSequenceNumber()))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        try{
            
            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(clientPublicKey);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getMovementId()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getTimeStamp()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(request.getMovementSignature().toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getNewBalance()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getRegisterSequenceNumber()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(request.getRegisterSignature().toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getSequenceNumber()).getBytes());
            
            
            /*ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(clientPublicKey);
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(request.getSequenceNumber()).getBytes());*/
            
            String hashMessageString = CryptographicFunctions.decrypt(clientPublicKey, request.getHashMessage().toByteArray());
            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);

            doubleEcho(CryptographicFunctions.hashString(new String(messageBytes.toByteArray())));

            this.serverRepo.updateBalance(Base64.getEncoder().encodeToString(clientPublicKey), request.getNewBalance());
            this.serverRepo.updateVersionNumber(Base64.getEncoder().encodeToString(clientPublicKey), request.getRegisterSequenceNumber());
            this.serverRepo.updateSignature(Base64.getEncoder().encodeToString(clientPublicKey), request.getRegisterSignature().toByteArray());
            this.serverRepo.receiveAmount(request.getMovementId(), "APPROVED", request.getMovementSignature().toByteArray(), request.getTimeStamp());
            
        }catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
        return receiveAmountResponse.newBuilder().build();
    }


    public auditResponse audit(ByteString clientPublicKey, int sequenceNumber) throws Exception{
    
        List <Integer> values = nonces.get(new String(clientPublicKey.toByteArray()));
        if(values != null && values.contains(sequenceNumber))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        
        try{
            float balance = this.serverRepo.getBalance(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            if (balance == -1)
                throw new ServerException(ErrorMessage.USER_ALREADY_EXISTS);

            List<Movement> movements = this.serverRepo.getCompletedMovements(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            List<Movement> pendingMovements = this.serverRepo.getPendingMovements(Base64.getEncoder().encodeToString(clientPublicKey.toByteArray()));
            movements.addAll(pendingMovements);

            if(isByzantine){
                if(movements.size() > 0){
                    Movement aux = movements.get(0);
                    Movement byzantineMov = Movement.newBuilder().setMovementID(aux.getMovementID())
                    .setMovementSignature(aux.getMovementSignature()).setTimeStamp(CryptographicFunctions.getTimeStamp())
                    .setSignatureKey(aux.getSignatureKey()).setAmount(33).setStatus("APPROVED").build();
                    movements.set(0,byzantineMov);
                }
            }

           
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
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
    }


    public highestRegisterSequenceNumberResponse getHighestRegSeqNumber(ByteString clientPublicKey,
     int sequenceNumber, ByteString hashMessage) throws Exception{

        String clientPublicKeyString = Base64.getEncoder().encodeToString(clientPublicKey.toByteArray());
        List <Integer> values = nonces.get(clientPublicKeyString);
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

            float balance = this.serverRepo.getBalance(clientPublicKeyString);
            if (balance == -1)
                throw new ServerException(ErrorMessage.NO_SUCH_USER);
            int registerSequenceNumber = this.serverRepo.getVersionNumber(clientPublicKeyString);
            byte[] registerSignature = this.serverRepo.getSignature(clientPublicKeyString);
            

            ByteArrayOutputStream replyBytes = new ByteArrayOutputStream();
            replyBytes.write(String.valueOf(sequenceNumber + 1).getBytes());
            
            String hashReply = CryptographicFunctions.hashString(new String(replyBytes.toByteArray()));
            ByteString encryptedHashReply = ByteString.copyFrom(CryptographicFunctions
            .encrypt(CryptographicFunctions.getServerPrivateKey("../crypto/"), hashReply.getBytes()));
        
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(new String(clientPublicKey.toByteArray()), nonce);

            highestRegisterSequenceNumberResponse response = highestRegisterSequenceNumberResponse.newBuilder().setBalance(balance)
            .setRegisterSignature(ByteString.copyFrom(registerSignature)).setRegisterSequenceNumber(registerSequenceNumber)
            .setSequenceNumber(sequenceNumber + 1).setHashMessage(encryptedHashReply).build();

            return response;
        }  
        catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR);  
        }
    }


    public writeBackRegisterResponse writeBackRegister(ByteString publicKey, int registerSequenceNumber, ByteString registerSignature, float balance, int messageSequenceNumber, ByteString hashMessage) throws Exception{
        List <Integer> values = nonces.get(new String(publicKey.toByteArray()));
        int highSeqNumber;
        if(values != null && values.contains(messageSequenceNumber))
            throw new ServerException(ErrorMessage.SEQUENCE_NUMBER);

        try{

            ByteArrayOutputStream messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKey.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(registerSequenceNumber).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(registerSignature.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(balance).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(messageSequenceNumber).getBytes());
            
            String hashMessageString = CryptographicFunctions.decrypt(publicKey.toByteArray(), hashMessage.toByteArray());

            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString))
                throw new ServerException(ErrorMessage.MESSAGE_INTEGRITY);

            doubleEcho(CryptographicFunctions.hashString(new String(messageBytes.toByteArray())));
            
            if(registerSequenceNumber > this.serverRepo.getVersionNumber(Base64.getEncoder().encodeToString(publicKey.toByteArray()))){
                this.serverRepo.updateBalance(Base64.getEncoder().encodeToString(publicKey.toByteArray()), balance);
                this.serverRepo.updateVersionNumber(Base64.getEncoder().encodeToString(publicKey.toByteArray()), registerSequenceNumber);
                this.serverRepo.updateSignature(Base64.getEncoder().encodeToString(publicKey.toByteArray()), registerSignature.toByteArray());
            }

            writeBackRegisterResponse response = writeBackRegisterResponse.newBuilder().build();
            return response;
        }  
        catch(GeneralSecurityException e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            throw new ServerException(ErrorMessage.INVALID_KEY_PAIR); 
        }
    }




    public void receive_echo(String hashRequest){
        int numberOfEchos;
        if(echos.containsKey(hashRequest))
            numberOfEchos = echos.get(hashRequest) + 1;
        else
            numberOfEchos = 1;
        echos.put(hashRequest, numberOfEchos);
    }


    public void receive_ready(String hashRequest){
        int numberOfReadies;
        if(readies.containsKey(hashRequest))
            numberOfReadies = readies.get(hashRequest) + 1;
        else
            numberOfReadies = 1;
        readies.put(hashRequest, numberOfReadies);
    }



    public void doubleEcho(String hashRequest) throws Exception{
        int cont, timeout = 0, numberOfEchos = 0;
        String target; 
        boolean sentReady = false;
        BFTBankingGrpc.BFTBankingStub stub;
        ManagedChannel channel;
        ArrayList<ManagedChannel> channels = new ArrayList<>();
        ArrayList<ManagedChannel> channels2 = new ArrayList<>();

        echoRequest request = echoRequest.newBuilder().setHashRequest(hashRequest).build();
        DoubleEchoObserver<echoResponse> echoObserver = new DoubleEchoObserver<>();
        
        for(cont = 0; cont < numberOfServers; cont++){
            if((basePort + cont) != serverPort){
                target = "localhost:" + (basePort + cont);
                channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
                stub = BFTBankingGrpc.newStub(channel);
                stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).echo(request, echoObserver);
                channels.add(channel);
            }
            else{
                if(echos.containsKey(hashRequest))
                    numberOfEchos = echos.get(hashRequest) + 1;
                else
                    numberOfEchos = 1;
                echos.put(hashRequest, numberOfEchos);
            }
        }
        
        if(!readies.containsKey(hashRequest))
            readies.put(hashRequest, 0);  
        
        while(echos.get(hashRequest) < byzantineQuorum && readies.get(hashRequest) < byzantineQuorum){ //Introduce timeout after which server sends exception saying there was more than f different requests sent by the client
            
            if(timeout>500)
                throw new ServerException(ErrorMessage.BYZANTINE_CLIENT_OR_MAX_SERVER_FAILURES);
            
            Thread.sleep(10);
            if((readies.get(hashRequest) > maxByzantineFaults) && (!sentReady)){    //Amplification step
                readyRequest request2 = readyRequest.newBuilder().setHashRequest(hashRequest).build();
                DoubleEchoObserver<readyResponse> readyObserver = new DoubleEchoObserver<>();

                for(cont = 0; cont < numberOfServers; cont++){
                    if((basePort + cont) != serverPort){
                        target = "localhost:" + (basePort + cont);
                        channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
                        stub = BFTBankingGrpc.newStub(channel);
                        stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).ready(request2, readyObserver);
                        channels2.add(channel);
                    }
                }
                readies.put(hashRequest, readies.get(hashRequest) + 1);
                sentReady = true;
            }
            timeout++;
        }

        if(!sentReady){                             
            readyRequest request2 = readyRequest.newBuilder().setHashRequest(hashRequest).build();
            DoubleEchoObserver<readyResponse> readyObserver = new DoubleEchoObserver<>();
            
            for(cont = 0; cont < numberOfServers; cont++){      //Retransmission step
                if((basePort + cont) != serverPort){
                    target = "localhost:" + (basePort + cont);
                    channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
                    stub = BFTBankingGrpc.newStub(channel);
                    stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).ready(request2, readyObserver);
                    channels2.add(channel);
                }
            }
            Thread.sleep(50);
        }

        for(ManagedChannel c: channels)
            c.shutdown();

        for(ManagedChannel c: channels2)
            c.shutdown();
    }
}