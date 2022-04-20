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
            sequenceNumber = new Random().nextInt(10000);
        }while(nonces.get(userID) != null && nonces.get(userID).contains(sequenceNumber));
        return sequenceNumber;
    }


    public void checkByzantineFaultQuantity(int byzantineFaultCont){
        if(byzantineFaultCont > possibleFailures){
            logger.log("More than " + possibleFailures + " server(s) have byzantine faults. Terminating...");
            System.exit(0);
        }
    }
    
    
    public void checkExceptionQuantity(ArrayList<StatusRuntimeException> logicExceptions,
        ArrayList<Exception> systemExceptions, ArrayList<ServerFrontend> frontends) throws Exception{
        
        
        if(logicExceptions.size() >= byzantineQuorum){
            throw new Exception(logicExceptions.get(0)); //Change later(identify majority of exceptions and only throw that one while regarding the others as having come from byzantine clients)
        }  //For byzantine exceptions increment unavailable counter and check again if it's > possible faults before returning majority exception
        
        else if(systemExceptions.size() > possibleFailures){
            logger.log("More than " + possibleFailures + " server(s) are unresponsive. Terminating...");
            System.exit(0);
        }
        
        /*else{ //possibly unecessary
            for (StatusRuntimeException ex : exceptions)
                logger.log("Exception with message: " + ex.getMessage());
            logger.log("Please retry operation...");
            return false;
        }*/
    }



    //-----------------------------------Open account----------------------------

    public void open(String password) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        String hashMessage, hashRegister;
        ByteString encryptedHashMessage, encryptedHashRegister;
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

        hashRegister = CryptographicFunctions.hashString("50:0:" + new String(publicKeyBytes));
        encryptedHashRegister = ByteString.copyFrom(CryptographicFunctions
        .encrypt(privateKey, hashRegister.getBytes()));

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
                checkExceptionQuantity(openAccountLogicExceptions, openAccountSystemExceptions, frontends);
            }
            
            //potentially delete seqnumber and hash message field in open account response as they don't seem to be necessary

            //eliminate byzantine responses wrongly signed or with wrong nonces (unecessary for open account)
            /*for(openAccountResponse response: openAccountResponses){ //Remove altered/duplicated replies
                if(i==byzantineQuorum)
                        break;
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
        }
    }


    //--------------------------------------Send amount--------------------------------------


    /*
    public void send(String password, int sourceID, int destID, float amount) throws Exception{
        
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber;
        ByteString encryptedHashMessage;
        byte[] sourcePublicKeyBytes, destPublicKeyBytes;
        Key privateKey;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();


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


        ServerObserver<sendAmountResponse> serverObs = new ServerObserver<sendAmountResponse>();

        synchronized(serverObs){
            for(cont = 0; cont <= numberOfServers; cont++){
                
                String _target = host + ":" + (basePort + cont);
                frontend = new ServerFrontend(target);
                frontend.openAccount(request,serverObs);
                frontends.add(frontend);
            }
        }




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
    }*/


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
        ByteString signatureAux;


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
                checkExceptionQuantity(checkAccountLogicExceptions, checkAccountSystemExceptions, frontends);
            }
            
            

            try{
                
                for(checkAccountResponse response: checkAccountResponses){ //Remove altered (message integrity compromissed) or duplicated (replay attacks) replies
                    
                    if(byzantineResponsesCont==byzantineQuorum)
                        break;
                    
                    System.out.println(response);
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
                

                for(checkAccountResponse response : checkAccountResponses){ //Obtain balance associated with highest seq number
                    seqNumberAux = response.getRegisterSequenceNumber(); 
                    signatureAux = response.getRegisterSignature(); 
                    balanceAux = response.getBalance();
                    signatureReplyRegister = CryptographicFunctions.decrypt(publicKeyBytes, signatureAux.toByteArray()); 
                    
                    signatureRegister = CryptographicFunctions.hashString(balanceAux + ":" + seqNumberAux + ":" + new String(publicKeyBytes));
                    if(!CryptographicFunctions.verifyMessageHash(signatureRegister.getBytes(), signatureReplyRegister)){
                        byzantineResponsesCont++;
                        checkAccountResponses.remove(response);          
                    }
                    else if(seqNumberAux > seqNumberFinal){
                            seqNumberFinal = seqNumberAux;
                            balanceFinal = balanceAux;
                    }
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                }
                
                
                for(checkAccountResponse response : checkAccountResponses){ //Remove byzantine replicas with wrongly signed movements
                    for(Movement mov : response.getPendingMovementsList()){
                        signatureReplyRegister = CryptographicFunctions.decrypt(publicKeyBytes, mov.getMovementSignature().toByteArray()); 
                        movementString = mov.getMovementID() + ":" + mov.getAmount() + ":" + mov.getStatus();
                        signatureRegister = CryptographicFunctions.hashString(movementString);
                        if(!CryptographicFunctions.verifyMessageHash(signatureRegister.getBytes(), signatureReplyRegister)){
                            byzantineResponsesCont++;
                            checkAccountResponses.remove(response);
                            break;         
                        }
                    }
                    checkByzantineFaultQuantity(byzantineResponsesCont);
                }
                       
            
                for(i=0; i<checkAccountResponses.size(); i++){//Check size of pendinglists from all valid replies to obtain majority of size 
                    sizeFrequencyAux = 0;
                    for(j=i+1; i<checkAccountResponses.size();j++){
                        if(checkAccountResponses.get(j).getPendingMovementsList().size() == checkAccountResponses.get(i).getPendingMovementsList().size()){
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

                List<Integer> nonce = new ArrayList<>(sequenceNumber);
                nonces.put(userID, nonce);

                
                System.out.println("Pending movements: ");
                for(Movement mov : checkAccountResponses.get(i).getPendingMovementsList()){
                    System.out.println("Movement " + mov.getMovementID() + ": " + mov.getAmount() + " (amount)");
                    
                }
                System.out.println("\nYour current balance: " + balanceFinal);

                for(ServerFrontend frontend : frontends)
                    frontend.close();

                }
            catch(Exception e){
                logger.log("Exception with message: " + e.getMessage() + " and cause:" + e.getCause());
            }
        }
    }

    /*
    public void receive(String password, int userID, int transferID){
        ByteArrayOutputStream messageBytes;
        String hashMessage;
        int sequenceNumber;
        ByteString encryptedHashMessage;
        byte[] publicKeyBytes;
        Key privateKey;
        ArrayList<ServerFrontend> frontends = new ArrayList<>();


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
        ArrayList<ServerFrontend> frontends = new ArrayList<>();


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
    }*/

}
