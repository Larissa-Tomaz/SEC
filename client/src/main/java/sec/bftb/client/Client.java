package sec.bftb.client;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;

import javax.lang.model.util.ElementScanner6;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
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
    private int noncesCleaner = 0;
    private boolean isByzantine = false;
    private Key privateKey, serverPublicKey;
    private final Logger logger;
    private ServerFrontend frontend;
    private Map<Integer, List<Integer>> nonces = new TreeMap<>();

   
    public Client(String _host, int base_port, int possible_failures, int number_of_servers){ //Remove target later
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
            sequenceNumber = new Random().nextInt(100000);
        }while(nonces.get(userID) != null && nonces.get(userID).contains(sequenceNumber));
        return sequenceNumber;
    }
    
    public void checkNoncesReset(){
        noncesCleaner++;
        if(noncesCleaner > 50000)
            nonces.clear();
            noncesCleaner = 0;
    }

    public ArrayList<Movement> orderMovementByTimeStamp(List<Movement> movements_original){
        ArrayList<Movement> movements = new ArrayList<Movement>(movements_original);
        
        for (int i = 0; i < movements.size() - 1; i++){
            for (int j = 0; j < movements.size() - i - 1; j++){
                if (movements.get(j).getTimeStamp() > movements.get(j + 1).getTimeStamp()) {
                    Movement temp = movements.get(j);
                    movements.set(j, movements.get(j + 1));
                    movements.set(j + 1, temp) ;
                }
            }
        }

        return movements;
    }


    public void checkByzantineFaultQuantity(int byzantineFaultCont) throws Exception{
        if(byzantineFaultCont > possibleFailures){
            throw new Exception("maxByzantineFaults");
        }
    }
    
    
    public void checkExceptionQuantity(ArrayList<StatusRuntimeException> logicExceptions,
        ArrayList<Exception> systemExceptions) throws Exception{
        
        int i = 0, j= 0,frequencyAux, frequencyFinal = -1, mostCommonPosition = 0;
        if(logicExceptions.size() >= byzantineQuorum){
            
            for(i=0; i<logicExceptions.size()-1; i++){
                frequencyAux = 0;
                for(j=i+1; j<logicExceptions.size();j++){
                    if(logicExceptions.get(i).getMessage() == logicExceptions.get(j).getMessage()){
                        frequencyAux++;
                    }
                }
                if(frequencyAux > frequencyFinal){
                        frequencyFinal = frequencyAux;
                        mostCommonPosition = i;
                }
            }        
            throw new Exception(logicExceptions.get(mostCommonPosition)); //Change later(identify majority of exceptions and only throw that one while regarding the others as having come from byzantine clients)
        }  
    
        else if(systemExceptions.size() > possibleFailures){
            throw new Exception("maxCrashFaults");
        }
    }


    public void changeIsByzantine(){
        System.out.println("Byzantine Flag is now set to " + !isByzantine);
        isByzantine = !isByzantine;
    }



    //-----------------------------------Open account----------------------------

    public void open(String password) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        String hashMessage, hashRegister;
        ByteString encryptedHashMessage, encryptedHashRegister;
        byte[] publicKeyBytes;
        KeyPair pair;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();
        int localUserID = 0, randPass = 0, i=0, byzantineResponsesCont = 0, targetPort;

        checkNoncesReset();
        
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

        
        
        hashRegister = CryptographicFunctions.hashString("50.0:0");
        encryptedHashRegister = ByteString.copyFrom(CryptographicFunctions
        .encrypt(privateKey, hashRegister.getBytes()));
        System.out.println(encryptedHashRegister+ "\n hashMessage" + encryptedHashMessage.size());

		openAccountRequest request = openAccountRequest.newBuilder()
        .setPublicKeyClient(ByteString.copyFrom(publicKeyBytes)).setRegisterSignature(encryptedHashRegister)
        .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();
        
        ServerObserver<openAccountResponse> serverObs = new ServerObserver<openAccountResponse>();

        synchronized(serverObs){
            for(cont = 0; cont < numberOfServers; cont++){
                target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                frontend.openAccount(request,serverObs);
                frontends.add(frontend);
            }
            
            System.out.println("Sent all requests.");
            do {
                try{
                    serverObs.wait(2000);
                    System.out.println("ResponseCollector size: " + serverObs.getResponseCollector().size());
                    System.out.println("LogicExceptionCollector size: " + serverObs.getLogicExceptionCollector().size());
                    System.out.println("SystemExceptionCollector size: " + serverObs.getSystemExceptionCollector().size());
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs.getResponseCollector().size() < byzantineQuorum && 
            serverObs.getLogicExceptionCollector().size() < byzantineQuorum && 
            serverObs.getSystemExceptionCollector().size() <= possibleFailures); 
            
            ArrayList<openAccountResponse> openAccountResponses = serverObs.getResponseCollector(); 
            ArrayList<StatusRuntimeException> openAccountLogicExceptions = serverObs.getLogicExceptionCollector();
            ArrayList<Exception> openAccountSystemExceptions = serverObs.getSystemExceptionCollector();
            
            if(openAccountLogicExceptions.size() >= byzantineQuorum || openAccountSystemExceptions.size() > possibleFailures){
                checkExceptionQuantity(openAccountLogicExceptions, openAccountSystemExceptions);
            }
            
            

            for(openAccountResponse response: openAccountResponses){ //Remove altered/replay attacked replies
                
                checkByzantineFaultQuantity(byzantineResponsesCont);

                System.out.println(response);
                if(response.getSequenceNumber() != sequenceNumber + 1){
                    logger.log("Invalid sequence number. Possible replay attack detected in one of the replica's reply.");
                    byzantineResponsesCont++;
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
                    byzantineResponsesCont++;           
                }
            }

            try{
                Map<Integer,Integer> valuePair = CryptographicFunctions.saveKeyPair(pair,password); 
                for(Map.Entry<Integer,Integer> entry : valuePair.entrySet()){
                    localUserID = entry.getKey();
                    randPass = entry.getValue();
                    break;
                }
              
                if(!nonces.containsKey(localUserID))
                    nonces.put(localUserID, new ArrayList<>(sequenceNumber));
                else
                    nonces.get(localUserID).add(sequenceNumber);
                System.out.println("Local user id: " + localUserID + ", Local access password: " + randPass + "-" + password);  
                
                
                for(ServerFrontend frontend : frontends)
                    frontend.close();
            }
            catch(Exception e){
                if(!e.getMessage().equals("maxByzantineFaults") && !e.getMessage().equals("maxCrashFaults"))
                    logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
                else if(e.getMessage().equals("maxByzantineFaults")){
                    Thread.sleep(1000);
                    logger.log("More than " + possibleFailures + " server(s) gave malicious/non-malicious byzantine responses. Please repeat the request...");
                }
                else{
                    Thread.sleep(3000);
                    logger.log("More than " + possibleFailures + " server(s) were unresponsive. Please repeat the request...");
                }
                for(ServerFrontend frontend : frontends)
                    frontend.close();
            }   

        }
    }




    //--------------------------------------Send amount--------------------------------------




    public void send(String password, int sourceID, int destID, float amount) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        boolean isValidated = false;
        String hashMessage, hashRegister, hashMovement;
        ByteString encryptedHashMessage, encryptedHashRegister, encryptedHashMovement;
        int sequenceNumber, byzantineResponsesCont = 0;
        long timeStamp;
        byte[] sourcePublicKeyBytes, destPublicKeyBytes;
        Key privateKey;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();


        String signatureReplyRegister, signatureRegister, movementString;
        int seqNumberAux, transferIDAux, transferIDFinal = -1, seqNumberFinal = -1;
        float balanceAux, balanceFinal = 0;
        ByteString signatureAux;


        //Preparation of first request which gets the values that will be written in the second request (isValidated = false)

        checkNoncesReset();
        
        timeStamp = CryptographicFunctions.getTimeStamp();
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
            messageBytes.write(Boolean.toString(isValidated).getBytes());
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
        .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).setIsValidated(isValidated).build();   


        ServerObserver<sendAmountResponse> serverObs = new ServerObserver<sendAmountResponse>();

        synchronized(serverObs){
            for(cont = 0; cont < numberOfServers; cont++){
                target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                frontend.sendAmount(request, serverObs);
                frontends.add(frontend);
            }
            
            System.out.println("Sent all requests.");
            do {
                try{
                    serverObs.wait(2000);
                    System.out.println("ResponseCollector size: " + serverObs.getResponseCollector().size());
                    System.out.println("LogicExceptionCollector size: " + serverObs.getLogicExceptionCollector().size());
                    System.out.println("SystemExceptionCollector size: " + serverObs.getSystemExceptionCollector().size());
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs.getResponseCollector().size() < byzantineQuorum && 
            serverObs.getLogicExceptionCollector().size() < byzantineQuorum && 
            serverObs.getSystemExceptionCollector().size() <= possibleFailures); 
            
            ArrayList<sendAmountResponse> sendAmountResponses = serverObs.getResponseCollector(); 
            ArrayList<StatusRuntimeException> sendAmountLogicExceptions = serverObs.getLogicExceptionCollector();
            ArrayList<Exception> sendAmountSystemExceptions = serverObs.getSystemExceptionCollector();
            
            if(sendAmountLogicExceptions.size() >= byzantineQuorum || sendAmountSystemExceptions.size() > possibleFailures){
                checkExceptionQuantity(sendAmountLogicExceptions, sendAmountSystemExceptions);
            }
            
            
            try{
                
                ArrayList<sendAmountResponse> sendAmountResponsesCopy = new ArrayList<>(sendAmountResponses);
                for(sendAmountResponse response: sendAmountResponsesCopy){ //Remove altered (message integrity compromissed) or duplicated (replay attacks) replies
                    
                    checkByzantineFaultQuantity(byzantineResponsesCont);

                    System.out.println(response);
                    if(response.getSequenceNumber() != sequenceNumber + 1){
                        logger.log("Invalid sequence number. Possible replay attack detected in one of the replica's reply.");
                        sendAmountResponses.remove(response);
                        byzantineResponsesCont++;
                        continue;
                    }
                    messageBytes = new ByteArrayOutputStream();
                    messageBytes.write(String.valueOf(response.getTransferId()).getBytes());
                    messageBytes.write(":".getBytes());
                    messageBytes.write(String.valueOf(response.getNewBalance()).getBytes());
                    messageBytes.write(":".getBytes());
                    messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
                    
                    serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
                    String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
                    if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                        logger.log("One of the replica's reply message had its integrity compromissed.");
                        sendAmountResponses.remove(response);
                        byzantineResponsesCont++;           
                    }
                }


                sendAmountResponsesCopy = new ArrayList<>(sendAmountResponses);
                for(sendAmountResponse response : sendAmountResponsesCopy){ //Obtain valid highest seq number and associated newBalance
                    seqNumberAux = response.getRegisterSequenceNumber(); 
                    signatureAux = response.getRegisterSignature(); 
                    balanceAux = response.getOldBalance();
                    transferIDAux = response.getTransferId();
                    signatureReplyRegister = CryptographicFunctions.decrypt(sourcePublicKeyBytes, signatureAux.toByteArray()); 
                    
                    signatureRegister = balanceAux + ":" + seqNumberAux;
                    if(!CryptographicFunctions.verifyMessageHash(signatureRegister.getBytes(), signatureReplyRegister)){
                        byzantineResponsesCont++;
                        sendAmountResponses.remove(response);
                        checkByzantineFaultQuantity(byzantineResponsesCont);
                        continue;          
                    }
                    if(seqNumberAux > seqNumberFinal){
                        seqNumberFinal = seqNumberAux;
                        balanceFinal = response.getNewBalance();
                    }
                    if(transferIDAux > transferIDFinal)
                        transferIDFinal = transferIDAux;    
                }

                if(!nonces.containsKey(sourceID))
                    nonces.put(sourceID, new ArrayList<>(sequenceNumber));
                else
                    nonces.get(sourceID).add(sequenceNumber);

                for(ServerFrontend frontend : frontends)
                    frontend.close();

            }
            catch(Exception e){
                if(!e.getMessage().equals("maxByzantineFaults") && !e.getMessage().equals("maxCrashFaults"))
                    logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
                else if(e.getMessage().equals("maxByzantineFaults")){
                    Thread.sleep(1000);
                    logger.log("More than " + possibleFailures + " server(s) gave malicious/non-malicious byzantine responses. Please repeat the request...");
                }
                else{
                    Thread.sleep(3000);
                    logger.log("More than " + possibleFailures + " server(s) were unresponsive. Please repeat the request...");
                }
                for(ServerFrontend frontend : frontends)
                    frontend.close();
                return;
            }
        }



        //Preparation of second request which writes definitevely the values got from first request (isValidated = true)
        
        isValidated = true;
        
        
        hashMovement = CryptographicFunctions.hashString(transferIDFinal + ":" + amount + ":PENDING:" + timeStamp);
        encryptedHashMovement = ByteString.copyFrom(CryptographicFunctions
        .encrypt(privateKey, hashMovement.getBytes()));

        seqNumberFinal++;
        hashRegister = CryptographicFunctions.hashString(balanceFinal + ":" + seqNumberFinal);
        encryptedHashRegister = ByteString.copyFrom(CryptographicFunctions
        .encrypt(privateKey, hashRegister.getBytes()));
    

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
            messageBytes.write(String.valueOf(transferIDFinal).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(timeStamp).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashMovement.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(balanceFinal).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(seqNumberFinal).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashRegister.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
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
        
        request = sendAmountRequest.newBuilder().setPublicKeySender(ByteString.copyFrom(sourcePublicKeyBytes))
        .setPublicKeyReceiver(ByteString.copyFrom(destPublicKeyBytes)).setAmount(amount).setTransferId(transferIDFinal)
        .setMovementSignature(encryptedHashMovement).setNewBalance(balanceFinal).setRegisterSequenceNumber(seqNumberFinal)
        .setRegisterSignature(encryptedHashRegister).setTimeStamp(timeStamp).setSequenceNumber(sequenceNumber)
        .setHashMessage(encryptedHashMessage).setIsValidated(isValidated).build();   

        sendAmountRequest request2 = sendAmountRequest.newBuilder().build();
        if(isByzantine){
            
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            sourcePublicKeyBytes = CryptographicFunctions.getClientPublicKey(sourceID).getEncoded();
            destPublicKeyBytes = CryptographicFunctions.getClientPublicKey(destID).getEncoded();

            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(sourcePublicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(destPublicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(amount * 20).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(transferIDFinal).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(timeStamp).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashMovement.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(balanceFinal * 30).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(seqNumberFinal).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashRegister.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            
            hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
            
            request2 = sendAmountRequest.newBuilder().setPublicKeySender(ByteString.copyFrom(sourcePublicKeyBytes))
            .setPublicKeyReceiver(ByteString.copyFrom(destPublicKeyBytes)).setAmount(amount * 20).setTransferId(transferIDFinal)
            .setMovementSignature(encryptedHashMovement).setNewBalance(balanceFinal * 30).setRegisterSequenceNumber(seqNumberFinal)
            .setRegisterSignature(encryptedHashRegister).setTimeStamp(timeStamp).setSequenceNumber(sequenceNumber)
            .setHashMessage(encryptedHashMessage).setIsValidated(isValidated).build();   
        }


        ServerObserver<sendAmountResponse> serverObs2 = new ServerObserver<sendAmountResponse>();

        synchronized(serverObs2){
            for(cont = 0; cont < numberOfServers; cont++){
                target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                if((isByzantine) && (cont >= numberOfServers/2))
                    frontend.sendAmount(request2, serverObs2);
                else
                    frontend.sendAmount(request, serverObs2);
                frontends.add(frontend);
            }
            
            System.out.println("Sent all requests.");
            do {
                try{
                    serverObs2.wait(2000);
                    System.out.println("ResponseCollector size: " + serverObs2.getResponseCollector().size());
                    System.out.println("LogicExceptionCollector size: " + serverObs2.getLogicExceptionCollector().size());
                    System.out.println("SystemExceptionCollector size: " + serverObs2.getSystemExceptionCollector().size());
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs2.getResponseCollector().size() < byzantineQuorum && 
            serverObs2.getLogicExceptionCollector().size() < byzantineQuorum && 
            serverObs2.getSystemExceptionCollector().size() <= possibleFailures); 
            
            ArrayList<StatusRuntimeException> sendAmountLogicExceptions2 = serverObs2.getLogicExceptionCollector();
            ArrayList<Exception> sendAmountSystemExceptions2 = serverObs2.getSystemExceptionCollector();
            
            if(sendAmountLogicExceptions2.size() >= byzantineQuorum || sendAmountSystemExceptions2.size() > possibleFailures){
                checkExceptionQuantity(sendAmountLogicExceptions2, sendAmountSystemExceptions2);
            }

            if(!nonces.containsKey(sourceID))
                    nonces.put(sourceID, new ArrayList<>(sequenceNumber));
                else
                    nonces.get(sourceID).add(sequenceNumber);

            for(ServerFrontend frontend : frontends)
                frontend.close();
        }

        System.out.println("Transfer succesfully created with id: " + transferIDFinal);
    }





    //---------------------------------Check account--------------------------------




    public void check(String password, int userID) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber;
        int byzantineResponsesCont = 0, i = 0;
        ByteString encryptedHashMessage;
        byte[] publicKeyBytes;
        Key privateKey;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();

        String signatureReplyRegister, signatureRegister, movementString;
        int seqNumberAux, transferIDFinal = -1, seqNumberFinal = -1;
        float balanceAux, balanceFinal = 0, transferAmountFinal = -1;
        boolean isValid = true;
        int n=0, j = 0, sizeFrequencyAux, sizeFrequencyFinal = -1, mostCommonPosition = -1;
        ByteString signatureAux, signatureFinal = ByteString.copyFrom("INITIALIZED".getBytes());


        checkNoncesReset();

        try{
            sequenceNumber = generateNonce(userID);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
        }
        catch (Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            return;
        }

		
        checkAccountRequest request = checkAccountRequest.newBuilder().setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
        .setSequenceNumber(sequenceNumber).build();   



        ServerObserver<checkAccountResponse> serverObs = new ServerObserver<checkAccountResponse>();

        synchronized(serverObs){
            for(cont = 0; cont < numberOfServers; cont++){  //Send all requests
                target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                frontend.checkAccount(request,serverObs);
                frontends.add(frontend);
            }
            
            System.out.println("Sent all requests.");
            do {
                try{
                    serverObs.wait(2000);
                    System.out.println("ResponseCollector size: " + serverObs.getResponseCollector().size());
                    System.out.println("LogicExceptionCollector size: " + serverObs.getLogicExceptionCollector().size());
                    System.out.println("SystemExceptionCollector size: " + serverObs.getSystemExceptionCollector().size());
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs.getResponseCollector().size() < byzantineQuorum && 
            serverObs.getLogicExceptionCollector().size() < byzantineQuorum && 
            serverObs.getSystemExceptionCollector().size() <= possibleFailures); 
            
            ArrayList<checkAccountResponse> checkAccountResponses = serverObs.getResponseCollector(); 
            ArrayList<StatusRuntimeException> checkAccountLogicExceptions = serverObs.getLogicExceptionCollector();
            ArrayList<Exception> checkAccountSystemExceptions = serverObs.getSystemExceptionCollector();
            
            if(checkAccountLogicExceptions.size() >= byzantineQuorum || checkAccountSystemExceptions.size() > possibleFailures){
                checkExceptionQuantity(checkAccountLogicExceptions, checkAccountSystemExceptions);
            }
            
            

            try{
                
                ArrayList<checkAccountResponse> checkAccountResponsesCopy = new ArrayList<>(checkAccountResponses);
                for(checkAccountResponse response: checkAccountResponsesCopy){ //Remove altered (message integrity compromissed) or duplicated (replay attacks) replies
                    
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                    
                    System.out.println(response);
                    System.out.println("Signature size: " + response.getRegisterSignature().toByteArray().length);
                    if(response.getSequenceNumber() != sequenceNumber + 1){
                        logger.log("Invalid sequence number. Possible replay attack detected in one of the replica's reply.");
                        checkAccountResponses.remove(response);
                        byzantineResponsesCont++;
                        continue;
                    }

                    messageBytes = new ByteArrayOutputStream();
                    messageBytes.write(response.getPendingMovementsList().toString().getBytes());
                    messageBytes.write(":".getBytes());
                    messageBytes.write(String.valueOf(response.getBalance()).getBytes());
                    messageBytes.write(":".getBytes());
                    messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
                    
                    serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
                    String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
                    if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                        logger.log("One of the replica's reply message had its integrity compromissed.");
                        checkAccountResponses.remove(response);
                        byzantineResponsesCont++;          
                    }
                }
                
                checkAccountResponsesCopy = new ArrayList<>(checkAccountResponses);
                for(checkAccountResponse response : checkAccountResponsesCopy){ //Obtain balance associated with highest seq number
                    seqNumberAux = response.getRegisterSequenceNumber(); 
                    signatureAux = response.getRegisterSignature(); 
                    balanceAux = response.getBalance();
                    signatureReplyRegister = CryptographicFunctions.decrypt(publicKeyBytes, signatureAux.toByteArray()); 
                    
                    signatureRegister = balanceAux + ":" + seqNumberAux;
                    if(!CryptographicFunctions.verifyMessageHash(signatureRegister.getBytes(),signatureReplyRegister)){
                        byzantineResponsesCont++;
                        checkAccountResponses.remove(response);
                    }
                    else if(seqNumberAux > seqNumberFinal){
                            seqNumberFinal = seqNumberAux;
                            balanceFinal = balanceAux;
                            signatureFinal = signatureAux;
                    }
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                }
                
                checkAccountResponsesCopy = new ArrayList<>(checkAccountResponses);
                for(checkAccountResponse response : checkAccountResponsesCopy){ //Remove byzantine replicas with wrongly signed movements
                    for(Movement mov : response.getPendingMovementsList()){
                        signatureReplyRegister = CryptographicFunctions.decrypt(mov.getSignatureKey().toByteArray(), mov.getMovementSignature().toByteArray()); 
                        
                        movementString = mov.getMovementID() + ":" + mov.getAmount() + ":" + mov.getStatus() + ":" + mov.getTimeStamp();
                        if(!CryptographicFunctions.verifyMessageHash(movementString.getBytes(), signatureReplyRegister)){
                            byzantineResponsesCont++;
                            checkAccountResponses.remove(response);
                            break;         
                        }
                    }
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                }
                       
            
                for(i=0; i<checkAccountResponses.size()-1; i++){//Check size of pendinglists from all valid replies to obtain majority of size 
                    sizeFrequencyAux = 0;
                    for(j=i+1; j<checkAccountResponses.size();j++){
                        if(checkAccountResponses.get(i).getPendingMovementsList().size() == checkAccountResponses.get(j).getPendingMovementsList().size()){
                            for(n=0; n < checkAccountResponses.get(i).getPendingMovementsList().size(); n++){ //Obtain majority agreement of transferIDs for all trasnfers(might need to order lists by transferid before doing this cycle)
                                if(checkAccountResponses.get(i).getPendingMovementsList().get(n).getMovementID() !=
                                    checkAccountResponses.get(j).getPendingMovementsList().get(n).getMovementID())
                                    isValid = false;
                                    break;
                            }
                            sizeFrequencyAux++;
                        }
                    }
                    if(sizeFrequencyAux > sizeFrequencyFinal && isValid){
                            sizeFrequencyFinal = sizeFrequencyAux;
                            mostCommonPosition = i;
                    }
                }        

                if(!nonces.containsKey(userID))
                    nonces.put(userID, new ArrayList<>(sequenceNumber));
                else
                    nonces.get(userID).add(sequenceNumber);

                writeBackRegister(userID, password, publicKeyBytes, balanceFinal, seqNumberFinal, signatureFinal);

                
                if(checkAccountResponses.get(i).getPendingMovementsList().size() == 0)
                    System.out.println("Pending movements: None");
                else{
                    System.out.println("Pending Movements: ");
                    ArrayList<Movement> orderedMovements = orderMovementByTimeStamp(checkAccountResponses.get(i).getPendingMovementsList());
                    for(Movement mov : orderedMovements)
                        System.out.println(" -Movement " + mov.getMovementID() + ": " + mov.getAmount() + " (amount)");
                }
                System.out.println("\nYour current balance: " + balanceFinal);

                for(ServerFrontend frontend : frontends)
                    frontend.close();

                }
            catch(Exception e){
                if(!e.getMessage().equals("maxByzantineFaults") && !e.getMessage().equals("maxCrashFaults"))
                    logger.log("Exception with message: " + e.getMessage());
                else if(e.getMessage().equals("maxByzantineFaults")){
                    Thread.sleep(1000);
                    logger.log("More than " + possibleFailures + " server(s) gave malicious/non-malicious byzantine responses. Please repeat the request...");
                }
                else{
                    Thread.sleep(3000);
                    logger.log("More than " + possibleFailures + " server(s) were unresponsive. Please repeat the request...");
                }
                for(ServerFrontend frontend : frontends)
                    frontend.close();
            }   
    
        }
    }

    
    public void receive(String password, int userID, int transferID) throws Exception{
        ByteArrayOutputStream messageBytes;
        String hashMessage, hashMovement, hashRegister;
        boolean isValidated = false;
        long timeStamp;
        int sequenceNumber, byzantineResponsesCont = 0;
        ByteString encryptedHashMessage, encryptedHashMovement, encryptedHashRegister;
        byte[] publicKeyBytes;
        Key privateKey;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();

        String signatureReplyRegister, signatureRegister, movementString;
        int seqNumberAux, transferIDAux, transferIDFinal = -1, seqNumberFinal = -1;
        float balanceAux, balanceFinal = 0, amountAux, amountFinal = -1;
        ByteString signatureAux;
        Movement movementAux, movementFinal;


        checkNoncesReset();
        
        timeStamp = CryptographicFunctions.getTimeStamp();
        sequenceNumber = generateNonce(userID);
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
        
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(transferID).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
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
        .setIsValidated(isValidated).setMovementId(transferID).setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();   

        ServerObserver<receiveAmountResponse> serverObs = new ServerObserver<receiveAmountResponse>();

        synchronized(serverObs){
            for(cont = 0; cont < numberOfServers; cont++){
                target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                frontend.receiveAmount(request, serverObs);
                frontends.add(frontend);
            }
            
            System.out.println("Sent all requests.");
            do {
                try{
                    serverObs.wait(2000);
                    System.out.println("ResponseCollector size: " + serverObs.getResponseCollector().size());
                    System.out.println("LogicExceptionCollector size: " + serverObs.getLogicExceptionCollector().size());
                    System.out.println("SystemExceptionCollector size: " + serverObs.getSystemExceptionCollector().size());
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs.getResponseCollector().size() < byzantineQuorum && 
            serverObs.getLogicExceptionCollector().size() < byzantineQuorum && 
            serverObs.getSystemExceptionCollector().size() <= possibleFailures); 
            
            ArrayList<receiveAmountResponse> receiveAmountResponses = serverObs.getResponseCollector(); 
            ArrayList<StatusRuntimeException> receiveAmountLogicExceptions = serverObs.getLogicExceptionCollector();
            ArrayList<Exception> receiveAmountSystemExceptions = serverObs.getSystemExceptionCollector();
            
            if(receiveAmountLogicExceptions.size() >= byzantineQuorum || receiveAmountSystemExceptions.size() > possibleFailures){
                checkExceptionQuantity(receiveAmountLogicExceptions, receiveAmountSystemExceptions);
            }


            try{
                
                ArrayList<receiveAmountResponse> receiveAmountResponsesCopy = new ArrayList<>(receiveAmountResponses);
                for(receiveAmountResponse response: receiveAmountResponsesCopy){ //Remove altered (message integrity compromissed) or duplicated (replay attacks) replies
                    
                    checkByzantineFaultQuantity(byzantineResponsesCont);

                    System.out.println(response);
                    if(response.getSequenceNumber() != sequenceNumber + 1){
                        logger.log("Invalid sequence number. Possible replay attack detected in one of the replica's reply.");
                        receiveAmountResponses.remove(response);
                        byzantineResponsesCont++;
                        continue;
                    }
                    messageBytes = new ByteArrayOutputStream();
                    messageBytes.write(String.valueOf(response.getMovement()).getBytes());
                    messageBytes.write(":".getBytes());
                    messageBytes.write(String.valueOf(response.getNewBalance()).getBytes());
                    messageBytes.write(":".getBytes());
                    messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
                    
                    serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
                    String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
                    if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                        logger.log("One of the replica's reply message had its integrity compromissed.");
                        receiveAmountResponses.remove(response);
                        byzantineResponsesCont++;           
                    }
                }


                receiveAmountResponsesCopy = new ArrayList<>(receiveAmountResponses);
                for(receiveAmountResponse response : receiveAmountResponsesCopy){ //Obtain valid <highestSeqNumber, balance> and valid <TransferID, amount, status> 
                    seqNumberAux = response.getRegisterSequenceNumber(); 
                    signatureAux = response.getRegisterSignature(); 
                    balanceAux = response.getOldBalance();

                    signatureReplyRegister = CryptographicFunctions.decrypt(publicKeyBytes, signatureAux.toByteArray()); 
                    signatureRegister = balanceAux + ":" + seqNumberAux;
                    if(!CryptographicFunctions.verifyMessageHash(signatureRegister.getBytes(), signatureReplyRegister)){
                        byzantineResponsesCont++;
                        receiveAmountResponses.remove(response);          
                    }

                    movementAux = response.getMovement();
                    signatureReplyRegister = CryptographicFunctions.decrypt(movementAux.getSignatureKey().toByteArray(), 
                    movementAux.getMovementSignature().toByteArray()); 
                    signatureRegister = movementAux.getMovementID() + ":" + movementAux.getAmount() + ":" + movementAux.getStatus() + ":" + movementAux.getTimeStamp();
                    if(!CryptographicFunctions.verifyMessageHash(signatureRegister.getBytes(), signatureReplyRegister)){
                        byzantineResponsesCont++;
                        receiveAmountResponses.remove(response);          
                    }
                    else if(seqNumberAux > seqNumberFinal){
                            seqNumberFinal = seqNumberAux;
                            balanceFinal = response.getNewBalance();
                            amountFinal = movementAux.getAmount();
                    }
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                }

                if(!nonces.containsKey(userID))
                    nonces.put(userID, new ArrayList<>(sequenceNumber));
                else
                    nonces.get(userID).add(sequenceNumber);

                for(ServerFrontend frontend : frontends)
                    frontend.close();

            }
            catch(Exception e){
                if(!e.getMessage().equals("maxByzantineFaults") && !e.getMessage().equals("maxCrashFaults"))
                    logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
                else if(e.getMessage().equals("maxByzantineFaults")){
                    Thread.sleep(1000);
                    logger.log("More than " + possibleFailures + " server(s) gave malicious/non-malicious byzantine responses. Please repeat the request...");
                }
                else{
                    Thread.sleep(3000);
                    logger.log("More than " + possibleFailures + " server(s) were unresponsive. Please repeat the request...");
                }
                for(ServerFrontend frontend : frontends)
                    frontend.close();
                return;
            }
        }


        //Preparation of second request which writes definitevely the values got from first request (isValidated = true)
        
        isValidated = true;
        
        hashMovement = CryptographicFunctions.hashString(transferID + ":" + amountFinal + ":APPROVED:" + timeStamp);
        encryptedHashMovement = ByteString.copyFrom(CryptographicFunctions
        .encrypt(privateKey, hashMovement.getBytes()));

        seqNumberFinal++;
        hashRegister = CryptographicFunctions.hashString(balanceFinal + ":" + seqNumberFinal);
        encryptedHashRegister = ByteString.copyFrom(CryptographicFunctions
        .encrypt(privateKey, hashRegister.getBytes()));
    

        sequenceNumber = generateNonce(userID);
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
            
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(transferID).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(timeStamp).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashMovement.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(balanceFinal).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(seqNumberFinal).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashRegister.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
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
        
        request = receiveAmountRequest.newBuilder().setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
        .setMovementId(transferID).setMovementSignature(encryptedHashMovement).setTimeStamp(timeStamp)
        .setNewBalance(balanceFinal).setRegisterSequenceNumber(seqNumberFinal)
        .setRegisterSignature(encryptedHashRegister).setSequenceNumber(sequenceNumber)
        .setHashMessage(encryptedHashMessage).setIsValidated(isValidated).build();   

        receiveAmountRequest request2 = receiveAmountRequest.newBuilder().build();
        if(isByzantine){
            
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
            
            long ts = CryptographicFunctions.getTimeStamp();

            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(transferID + 20).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(ts).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashMovement.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(balanceFinal * 20).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(seqNumberFinal + 10).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(encryptedHashRegister.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(Boolean.toString(isValidated).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            
            hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
            
            request2 = receiveAmountRequest.newBuilder().setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
            .setMovementId(transferID + 20).setMovementSignature(encryptedHashMovement)
            .setTimeStamp(ts).setNewBalance(balanceFinal * 20).setRegisterSequenceNumber(seqNumberFinal + 10)
            .setRegisterSignature(encryptedHashRegister).setSequenceNumber(sequenceNumber)
            .setHashMessage(encryptedHashMessage).setIsValidated(isValidated).build();   
        }


        ServerObserver<receiveAmountResponse> serverObs2 = new ServerObserver<receiveAmountResponse>();

        synchronized(serverObs2){
            for(cont = 0; cont < numberOfServers; cont++){
                target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                if((isByzantine) && (cont >= numberOfServers/2))
                    frontend.receiveAmount(request2, serverObs2);
                else
                    frontend.receiveAmount(request, serverObs2);
                frontends.add(frontend);
            }
            
            System.out.println("Sent all requests.");
            do {
                try{
                    serverObs2.wait(2000);
                    System.out.println("ResponseCollector size: " + serverObs2.getResponseCollector().size());
                    System.out.println("LogicExceptionCollector size: " + serverObs2.getLogicExceptionCollector().size());
                    System.out.println("SystemExceptionCollector size: " + serverObs2.getSystemExceptionCollector().size());
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs2.getResponseCollector().size() < byzantineQuorum && 
            serverObs2.getLogicExceptionCollector().size() < byzantineQuorum && 
            serverObs2.getSystemExceptionCollector().size() <= possibleFailures); 
            
            ArrayList<StatusRuntimeException> sendAmountLogicExceptions2 = serverObs2.getLogicExceptionCollector();
            ArrayList<Exception> sendAmountSystemExceptions2 = serverObs2.getSystemExceptionCollector();
            
            if(sendAmountLogicExceptions2.size() >= byzantineQuorum || sendAmountSystemExceptions2.size() > possibleFailures){
                checkExceptionQuantity(sendAmountLogicExceptions2, sendAmountSystemExceptions2);
            }

            if(!nonces.containsKey(userID))
                nonces.put(userID, new ArrayList<>(sequenceNumber));
            else
                nonces.get(userID).add(sequenceNumber);

            for(ServerFrontend frontend : frontends)
                frontend.close();
        }
        System.out.println("Transfer accepted, amount received.");
    
    }


    
    //----------------------------Audit-----------------------------


    public void audit(String password, int userID) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber, byzantineResponsesCont = 0;
        ByteString encryptedHashMessage;
        byte[] publicKeyBytes;
        Key privateKey;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();

        String signatureReplyRegister, signatureRegister, movementString;
        boolean isValid = true;
        int sizeFrequencyAux, i = 0, n=0, j = 0, sizeFrequencyFinal = -1, mostCommonPosition = -1,  transferIDFinal = -1;
        //ByteString signatureAux;


        checkNoncesReset();

        sequenceNumber = generateNonce(userID);
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
        }
        catch (Exception e){
            logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            return;
        }
		
        auditRequest request = auditRequest.newBuilder().setPublicKeyClient(ByteString.copyFrom(publicKeyBytes))
        .setSequenceNumber(sequenceNumber).build();   

        ServerObserver<auditResponse> serverObs = new ServerObserver<auditResponse>();

        synchronized(serverObs){
            for(cont = 0; cont < numberOfServers; cont++){  //Send all requests
                target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                frontend.audit(request,serverObs);
                frontends.add(frontend);
            }
            
            System.out.println("Sent all requests.");
            do {
                try{
                    serverObs.wait(2000);
                    System.out.println("ResponseCollector size: " + serverObs.getResponseCollector().size());
                    System.out.println("LogicExceptionCollector size: " + serverObs.getLogicExceptionCollector().size());
                    System.out.println("SystemExceptionCollector size: " + serverObs.getSystemExceptionCollector().size());
                }catch (InterruptedException e) {
                    System.out.println("Wait interrupted");
                    throw e;
                }
            }
            while(serverObs.getResponseCollector().size() < byzantineQuorum && 
            serverObs.getLogicExceptionCollector().size() < byzantineQuorum && 
            serverObs.getSystemExceptionCollector().size() <= possibleFailures); 
            
            ArrayList<auditResponse> auditResponses = serverObs.getResponseCollector(); 
            ArrayList<StatusRuntimeException> auditLogicExceptions = serverObs.getLogicExceptionCollector();
            ArrayList<Exception> auditSystemExceptions = serverObs.getSystemExceptionCollector();
            
            if(auditLogicExceptions.size() >= byzantineQuorum || auditSystemExceptions.size() > possibleFailures){
                checkExceptionQuantity(auditLogicExceptions, auditSystemExceptions);
            }
            
            try{

                ArrayList<auditResponse> auditResponsesCopy = new ArrayList<>(auditResponses);
                for(auditResponse response: auditResponsesCopy){ //Remove altered (message integrity compromissed) or duplicated (replay attacks) replies
                    
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                    
                    System.out.println(response);
                    if(response.getSequenceNumber() != sequenceNumber + 1){
                        logger.log("Invalid sequence number. Possible replay attack detected in one of the replica's reply.");
                        auditResponses.remove(response);
                        byzantineResponsesCont++;
                        continue;
                    }

                    messageBytes = new ByteArrayOutputStream();
                    messageBytes.write(response.getConfirmedMovementsList().toString().getBytes());
                    messageBytes.write(":".getBytes());
                    messageBytes.write(String.valueOf(response.getSequenceNumber()).getBytes());
                    
                    serverPublicKey = CryptographicFunctions.getServerPublicKey("../crypto/");
                    String hashMessageString = CryptographicFunctions.decrypt(serverPublicKey.getEncoded(), response.getHashMessage().toByteArray()); 
                    if(!CryptographicFunctions.verifyMessageHash(messageBytes.toByteArray(), hashMessageString)){
                        logger.log("One of the replica's reply message had its integrity compromissed.");
                        auditResponses.remove(response);
                        byzantineResponsesCont++;          
                    }
                }

                auditResponsesCopy = new ArrayList<>(auditResponses);
                for(auditResponse response : auditResponsesCopy){ //Remove byzantine replicas with wrongly signed movements
                    for(Movement mov : response.getConfirmedMovementsList()){
                        signatureReplyRegister = CryptographicFunctions.decrypt(mov.getSignatureKey().toByteArray(), mov.getMovementSignature().toByteArray()); 

                        movementString = mov.getMovementID() + ":" + mov.getAmount() + ":" + mov.getStatus() + ":" + mov.getTimeStamp();
                        if(!CryptographicFunctions.verifyMessageHash(movementString.getBytes(), signatureReplyRegister)){
                            byzantineResponsesCont++;
                            auditResponses.remove(response);
                            break;         
                        }
                    }
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                }
                       
            
                for(i=0; i<auditResponses.size()-1; i++){//Check size of confirmedlists from all valid replies to obtain majority of size 
                    sizeFrequencyAux = 0;
                    for(j=i+1; j<auditResponses.size();j++){
                        if(auditResponses.get(i).getConfirmedMovementsList().size() == auditResponses.get(j).getConfirmedMovementsList().size()){
                            for(n=0; n < auditResponses.get(i).getConfirmedMovementsList().size(); n++){ //Obtain majority agreement of transferIDs for all trasnfers(might need to order lists by transferid before doing this cycle)
                                if(auditResponses.get(i).getConfirmedMovementsList().get(n).getMovementID() !=
                                    auditResponses.get(j).getConfirmedMovementsList().get(n).getMovementID())
                                    isValid = false;
                                    break;
                            }
                            sizeFrequencyAux++;
                        }
                    }
                    if(sizeFrequencyAux > sizeFrequencyFinal && isValid){
                            sizeFrequencyFinal = sizeFrequencyAux;
                            mostCommonPosition = i;
                    }
                }        

                if(!nonces.containsKey(userID))
                    nonces.put(userID, new ArrayList<>(sequenceNumber));
                else
                    nonces.get(userID).add(sequenceNumber);

                if(auditResponses.get(i).getConfirmedMovementsList().size() == 0)
                    System.out.println("Movement History: None");
                else{
                    ArrayList<Movement> orderedMovements = orderMovementByTimeStamp(auditResponses.get(i).getConfirmedMovementsList());
                    
                    System.out.println("Movement History:");
                    for(Movement mov : orderedMovements){
                        System.out.println("  -Movement " + mov.getMovementID() + ":");
                        System.out.println("    < Status: " + mov.getStatus() + ", " + mov.getDirectionOfTransfer() + " amount: " + mov.getAmount() + " >");
                    }
                }

                for(ServerFrontend frontend : frontends)
                    frontend.close();
            }
            catch(Exception e){
                if(!e.getMessage().equals("maxByzantineFaults") && !e.getMessage().equals("maxCrashFaults"))
                    logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
                else if(e.getMessage().equals("maxByzantineFaults")){
                    Thread.sleep(1000);
                    logger.log("More than " + possibleFailures + " server(s) gave malicious/non-malicious byzantine responses. Please repeat the request...");
                }
                else{
                    Thread.sleep(3000);
                    logger.log("More than " + possibleFailures + " server(s) were unresponsive. Please repeat the request...");
                }
                for(ServerFrontend frontend : frontends)
                    frontend.close();
            }   

        }
    }

    //---------------------------------------------------------WriteBack------------------------------------------------

    public void writeBackRegister(int userID, String password, byte[] publicKeyBytes, float balance, int registerSequenceNumber, ByteString registerSignature) throws Exception{

        ByteArrayOutputStream messageBytes;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();
        int sequenceNumber = generateNonce(userID);
        
        
        try{
            privateKey = CryptographicFunctions.getClientPrivateKey(password);
            publicKeyBytes = CryptographicFunctions.getClientPublicKey(userID).getEncoded();
            
            messageBytes = new ByteArrayOutputStream();
            messageBytes.write(publicKeyBytes);
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(registerSequenceNumber).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(registerSignature.toByteArray());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(balance).getBytes());
            messageBytes.write(":".getBytes());
            messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            
            String hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
            ByteString encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
            .encrypt(privateKey, hashMessage.getBytes()));
            
            
            writeBackRegisterRequest request = writeBackRegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKeyBytes))
            .setBalance(balance).setRegisterSequenceNumber(registerSequenceNumber).setRegisterSignature(registerSignature)
            .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();   

            
            writeBackRegisterRequest request2 = writeBackRegisterRequest.newBuilder().build();
            if(isByzantine){
                messageBytes = new ByteArrayOutputStream();
                messageBytes.write(publicKeyBytes);
                messageBytes.write(":".getBytes());
                messageBytes.write(String.valueOf(registerSequenceNumber + 20).getBytes());
                messageBytes.write(":".getBytes());
                messageBytes.write(registerSignature.toByteArray());
                messageBytes.write(":".getBytes());
                messageBytes.write(String.valueOf(balance + 70).getBytes());
                messageBytes.write(":".getBytes());
                messageBytes.write(String.valueOf(sequenceNumber).getBytes());
            
            
                hashMessage = CryptographicFunctions.hashString(new String(messageBytes.toByteArray()));
                encryptedHashMessage = ByteString.copyFrom(CryptographicFunctions
                .encrypt(privateKey, hashMessage.getBytes()));
                
                
                request2 = writeBackRegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKeyBytes))
                .setBalance(balance + 70).setRegisterSequenceNumber(registerSequenceNumber + 20).setRegisterSignature(registerSignature)
                .setSequenceNumber(sequenceNumber).setHashMessage(encryptedHashMessage).build();   
            }



            ServerObserver<writeBackRegisterResponse> serverObs = new ServerObserver<writeBackRegisterResponse>();

            synchronized(serverObs){
                for(cont = 0; cont < numberOfServers; cont++){
                    target = host + ":" + (basePort + cont);
                    frontend = new ServerFrontend(target);
                    if((isByzantine) && (cont >= numberOfServers/2))
                        frontend.writeBackRegister(request2, serverObs);
                    else
                        frontend.writeBackRegister(request, serverObs);
                    frontends.add(frontend);
                }
                
                System.out.println("Sent all requests.");
                do {
                    try{
                        serverObs.wait(2000);
                        System.out.println("ResponseCollector size: " + serverObs.getResponseCollector().size());
                        System.out.println("LogicExceptionCollector size: " + serverObs.getLogicExceptionCollector().size());
                        System.out.println("SystemExceptionCollector size: " + serverObs.getSystemExceptionCollector().size());
                    }catch (InterruptedException e) {
                        System.out.println("Wait interrupted");
                        throw e;
                    }
                }
                while(serverObs.getResponseCollector().size() < byzantineQuorum && 
                serverObs.getLogicExceptionCollector().size() < byzantineQuorum && 
                serverObs.getSystemExceptionCollector().size() <= possibleFailures); 
                
                ArrayList<StatusRuntimeException> writeBackRegisterLogicExceptions = serverObs.getLogicExceptionCollector();
                ArrayList<Exception> writeBackRegisterSystemExceptions = serverObs.getSystemExceptionCollector();
                
                if(writeBackRegisterLogicExceptions.size() >= byzantineQuorum || writeBackRegisterSystemExceptions.size() > possibleFailures){
                    checkExceptionQuantity(writeBackRegisterLogicExceptions, writeBackRegisterSystemExceptions);
                }

                if(!nonces.containsKey(userID))
                    nonces.put(userID, new ArrayList<>(sequenceNumber));
                else
                    nonces.get(userID).add(sequenceNumber);

                for(ServerFrontend frontend : frontends)
                    frontend.close();
            }
        }catch(Exception e){
            for(ServerFrontend frontend : frontends)
                frontend.close();
            throw new Exception(e);
        }
    }
}
