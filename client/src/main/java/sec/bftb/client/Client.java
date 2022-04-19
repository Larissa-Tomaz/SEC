package sec.bftb.client;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import javax.lang.model.util.ElementScanner6;

import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import sec.bftb.crypto.*;
import sec.bftb.client.Logger;
import sec.bftb.client.ServerFrontend;


import sec.bftb.grpc.Contract.*;

public class Client {

    private String target;
    private String host;
    private int basePort;
    private int byzantineQuorum;
    private int numberOfServers;
    private int possibleFailures;
    private int cont;
    private Key privateKey, serverPublicKey;
    private final Logger logger;
    private ServerFrontend frontend;
    private Map<Integer, List<Integer>> nonces = new TreeMap<>();

   
    public Client(String _host, int base_port, String _target, int possible_failures, int number_of_servers){ //Remove target later
        target = _target;
        host = _host;
        basePort = base_port;
        numberOfServers = number_of_servers;
        byzantineQuorum = (2 * possible_failures) + 1; //2f+1
        possibleFailures = possible_failures;
        logger = new Logger("Client", "App");
    }

    public int generateNonce(int userID){
        int sequenceNumber;
        do{
            sequenceNumber = new Random().nextInt(10000);
        }while(nonces.get(userID) != null && nonces.get(userID).contains(sequenceNumber));
        return sequenceNumber;
    }


    public boolean checkExceptionQuantity(ArrayList<StatusRuntimeException> exceptions) throws Exception{
        Exception exception = new Exception();
        int invalidArgCount = 0, unavailableCount = 0;
        for(StatusRuntimeException e : exceptions){
                if(e.getStatus().getCode().equals(Status.INVALID_ARGUMENT.getCode())){
                    exception = e;
                    invalidArgCount++;
                }
                else if(e.getStatus().getCode().equals(Status.UNAVAILABLE.getCode())){
                    unavailableCount++;
                }
        }
        if(unavailableCount > possibleFailures){
            logger.log("More than " + possibleFailures + " servers are down. Terminating...");
            System.exit(0);
        }
        else if(invalidArgCount >= byzantineQuorum){
            throw new Exception(exception); //Change later(identify majority of exceptions and only throw that one)
        }
        else{
            for (StatusRuntimeException ex : exceptions)
                logger.log("Exception with message: " + ex.getMessage());
            logger.log("Please retry operation...");
            return false;
        }
        return true;
    }



    //-----------------------------------Open account----------------------------

    public void open(String password) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        String hashMessage, _target;
        ByteString encryptedHashMessage;
        byte[] publicKeyBytes;
        KeyPair pair;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();
        int localUserID = 0, randPass = 0, i=0, targetPort;

        int sequenceNumber = new Random().nextInt(10000);
        
        try{
            pair = CryptographicFunctions.createKeyPair();
            publicKeyBytes = pair.getPublic().getEncoded();
            privateKey = pair.getPrivate();

            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
        }
        catch (Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            return;
        }

		openAccountRequest request = openAccountRequest.newBuilder()
        .setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
        .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();
        
        ServerObserver<openAccountResponse> serverObs = new ServerObserver<openAccountResponse>();

        synchronized(serverObs){
            for(cont = 0; cont <= numberOfServers; cont++){
                targetPort = basePort + cont;
                _target = host + ":" + targetPort;
                frontend = new ServerFrontend(target);
                frontend.openAccount(request);
                frontends.add(frontend);
            }

            do {
                try{
                    serverObs.wait(2000);
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs.getResponseCollector().size() < byzantineQuorum || serverObs.getExceptionCollector().size() < byzantineQuorum); 
            
            ArrayList<openAccountResponse> openAccountResponses = serverObs.getResponseCollector(); //Make a for cycle now to check each response out of this list (Implement (1,N) atomic register )
            ArrayList<StatusRuntimeException> openAccountExceptions = serverObs.getExceptionCollector();
            
            if(openAccountExceptions.size() >= byzantineQuorum){
                if(!checkExceptionQuantity(openAccountExceptions))
                    return;
            }
            
            //eliminate byzantine responses wrongly signed or with wrong nonces
            /*for(openAccountResponse response: openAccountResponses){ //Remove altered/duplicated replies
                i++;
                System.out.println(response);
                if(response.getSequenceNumber() != sequenceNumber + 1){
                    logger.log("Invalid sequence number. Possible replay attack detected in one of the replica's reply.");
                    openAccountResponses.remove(response);
                    continue;
                }
                messageBytes = new ByteArrayOutputStream();
                messageBytes.write(String.valueOf(response.getBalance()).getBytes());
                messageBytes.write(":".getBytes());
                messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
                
                serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
                String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
                if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                    logger.log("One of the replica's reply message had its integrity compromissed.");
                    openAccountResponses.remove(response);           
                }
                if(i==byzantineQuorum)
                    break;
            }*/

            try{
                Map<Integer,Integer> valuePair = CryptographicFunctions.saveKeyPair(pair,password); 
                for(Map.Entry<Integer,Integer> entry : valuePair.entrySet()){
                    localUserID = entry.getKey();
                    randPass = entry.getValue();
                    break;
                }
                List<Integer> nonce = new ArrayList<>(sequenceNumber);
                nonces.put(localUserID, nonce);
                System.out.println("Local user id: " + localUserID + ", Local access password: " + randPass + "-" + password);  
                
                
                for(ServerFrontend frontend : frontends)
                frontend.close();
            }
            catch(Exception e){
                logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            }   


            /*response = readResp.get(0);
			aux = response.getSequence();
            for(i=0; i < openAccountResponses.size(); i++){

                response = readResp.get(0);
			aux = response.getSequence();
			cid_aux = response.getCid();
			System.out.println("Frontend received answer with sequence number = " + aux + " ...");
			for(int i = 1; i<readQuorum ; i++) {
				System.out.println("Frontend received answer with sequence number = " + readResp.get(i).getSequence() + " ...");
				if(readResp.get(i).getSequence() > aux) {
					response = readResp.get(i);
					aux = response.getSequence();
					cid_aux = response.getCid();
				}
				else if(readResp.get(i).getSequence() == aux && readResp.get(i).getCid()>cid_aux)  {
					response = readResp.get(i);
					aux = response.getSequence();
					cid_aux = response.getCid();
				}
			}*/  
        }
    }


    //--------------------------------------Send amount--------------------------------------



    public void send(String password, int sourceID, int destID, float amount) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber;
        ByteString encryptedHashMessage;
        byte[] sourcePublicKeyBytes, destPublicKeyBytes;
        Key privateKey;


        sequenceNumber = generateNonce(sourceID);
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            sourcePublicKeyBytes = CryptographicFunctions.getClientPublicKey(sourceID).getEncoded();
            destPublicKeyBytes = CryptographicFunctions.getClientPublicKey(destID).getEncoded();

            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(sourcePublicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(destPublicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(amount).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
        }
        catch (Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            return;
        }

		
        sendAmountRequest request = sendAmountRequest.newBuilder().setPublicKeySender(ByteString.copyFrom(sourcePublicKeyBytes))
        .setPublicKeyReceiver(ByteString.copyFrom(destPublicKeyBytes)).setAmount(amount)
        .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();   

		frontend = new ServerFrontend(target);
        sendAmountResponse response = frontend.sendAmount(request);
        frontend = new ServerFrontend(target);
        if(response.getSequenceNumber() != sequenceNumber + 1){
            logger.log("Invalid sequence number. Possible replay attack detected.");
            return;
        }

        
        try{
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(String.valueOf(response.getTransferId()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
            
            serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
            String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                logger.log("Message reply integrity compromissed.");
                return;
            }
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(sourceID, nonce);

            System.out.println("Transfer succesfully created with id: " + response.getTransferId());
        }
        catch(Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
        }
    }


    //---------------------------------Check account--------------------------------


    public void check(String password, int userID){
        
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber;
        ByteString encryptedHashMessage;
        byte[] publicKeyBytes;
        Key privateKey;


        sequenceNumber = generateNonce(userID);
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
        
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
        }
        catch (Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            return;
        }

		
        checkAccountRequest request = checkAccountRequest.newBuilder().setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
        .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();   

        frontend = new ServerFrontend(target);
		checkAccountResponse response = frontend.checkAccount(request);
        frontend.close();
        if(response.getSequenceNumber() != sequenceNumber + 1){
            logger.log("Invalid sequence number. Possible replay attack detected.");
            return;
        }

        
        try{
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(response.getPendingMovementsList().toString().getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(response.getBalance()).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
            
            serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
            String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                logger.log("Message reply integrity compromissed.");
                return;
            }
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(userID, nonce);

            System.out.println("Pending movements: ");
            for(Movement mov : response.getPendingMovementsList()){
                System.out.println("Movement " + mov.getMovementID() + ": " + mov.getAmount() + " (amount)");
                
            }
            System.out.println("\nYour current balance: " + response.getBalance());
        }
        catch(Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
        }
    }



    public void receive(String password, int userID, int transferID){
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber;
        ByteString encryptedHashMessage;
        byte[] publicKeyBytes;
        Key privateKey;


        sequenceNumber = generateNonce(userID);
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
        
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(transferID).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
        }
        catch (Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            return;
        }

		
        receiveAmountRequest request = receiveAmountRequest.newBuilder().setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
        .setMovementId(transferID).setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();   

		frontend = new ServerFrontend(target);
        receiveAmountResponse response = frontend.receiveAmount(request);
        frontend.close();
        if(response.getSequenceNumber() != sequenceNumber + 1){
            logger.log("Invalid sequence number. Possible replay attack detected.");
            return;
        }

        
        try{
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
            
            serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
            String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                logger.log("Message reply integrity compromissed.");
                return;
            }
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(userID, nonce);

            System.out.println("Transfer accepted, amount received.");
        }
        catch(Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
        }
    }



    //----------------------------Audit-----------------------------



    public void audit(String password, int userID){
        
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber;
        ByteString encryptedHashMessage;
        byte[] publicKeyBytes;
        Key privateKey;


        sequenceNumber = generateNonce(userID);
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
        
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
        }
        catch (Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            return;
        }

		
        auditRequest request = auditRequest.newBuilder().setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
        .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();   

		frontend = new ServerFrontend(target);
        auditResponse response = frontend.audit(request);
        frontend.close();
        if(response.getSequenceNumber() != sequenceNumber + 1){
            logger.log("Invalid sequence number. Possible replay attack detected.");
            return;
        }

        
        try{
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(response.getConfirmedMovementsList().toString().getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
            
            serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
            String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
            if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                logger.log("Message reply integrity compromissed.");
                return;
            }
        
            List<Integer> nonce = new ArrayList<>(sequenceNumber);
            nonces.put(userID, nonce);

            System.out.println("Accepted movements: ");
            for(Movement mov : response.getConfirmedMovementsList()){
                System.out.println("Movement " + mov.getMovementID() + ":");
                System.out.println("Status: " + mov.getStatus() + ", " + mov.getDirectionOfTransfer() + " amount: " + mov.getAmount());
            }
        }
        catch(Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
        }
    }

}
