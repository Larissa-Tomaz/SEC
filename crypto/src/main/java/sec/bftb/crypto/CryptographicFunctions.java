package sec.bftb.crypto;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.*;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.io.*;
import java.sql.Timestamp;
import java.math.BigInteger;
import java.nio.file.*;



public class CryptographicFunctions{

    //------------------------------Create/Obtain Keys-------------------------


    public static KeyPair createKeyPair() throws NoSuchAlgorithmException, Exception{
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }
      

    public static Map<Integer,Integer> saveKeyPair (KeyPair keypair, String password) throws Exception{
        
        OutputStream os;
        int rand;
        Key publicKey = keypair.getPublic();
        Key privateKey = keypair.getPrivate();
        int cont = 10000;
        File file = null;
        
        do{
            cont++;
            file = new File("../crypto/keys/publicKeys/" + cont + "-PublicKey");
        } while(!file.createNewFile());

        os = new FileOutputStream(file);
        os.write(publicKey.getEncoded());
        os.close();

        do{
            rand = new Random().nextInt(100);
            file = new File("../crypto/keys/privateKeys/" + rand + "-" + password + "-PrivateKey");
        } while(!file.createNewFile());
    
        os = new FileOutputStream(file);
        os.write(privateKey.getEncoded());
        os.close();

        Map<Integer,Integer> pair = new TreeMap<>();
        pair.put(cont,rand);

        return pair;
    }


    
    public static Key getClientPublicKey(int userID) throws Exception {
        try{
            byte[] keyBytes = Files.readAllBytes(Paths.get("../crypto/keys/publicKeys/" + userID + "-PublicKey"));
    
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }catch(IOException e){
            throw new Exception("Wrong userID or password.");
        }
    }

    public static Key getServerPublicKey(String path) throws Exception {
        try{
            byte[] keyBytes = Files.readAllBytes(Paths.get(path + "keys/serverPublicKey"));
        
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }catch(IOException e){
            throw new Exception("Server's public key not found");
        }
    }
    
    public static Key getClientPrivateKey(String password) throws Exception {
        try{
            byte[] keyBytes = Files.readAllBytes(Paths.get("../crypto/keys/privateKeys/" + password + "-PrivateKey"));
        
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }catch(IOException e){
            throw new Exception("Wrong userID or password.");
        }
    }

    public static Key getServerPrivateKey(String path) throws Exception {
        try{
            byte[] keyBytes = Files.readAllBytes(Paths.get(path + "keys/serverPrivateKey"));
        
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }catch(IOException e){
            throw new Exception("Server's private key not found");
        }
    }


    //---------------------------TimeStamp operations---------------------------


    public static long getTimeStamp(){

        Timestamp timestampNow = new Timestamp(System.currentTimeMillis());
        long timeStampLong = timestampNow.getTime();

        return timeStampLong;
    }

    //---------------------------Hash Functions----------------------------------

    
    public static String hashString(String secretString) throws NoSuchAlgorithmException, NoSuchProviderException{

        String hashtext = null;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        byte[] messageDigest = md.digest(secretString.getBytes());
        hashtext = convertToHex(messageDigest);
        return hashtext;
    }


    public static String convertToHex(byte[] messageDigest) {
        BigInteger value = new BigInteger(1, messageDigest);
        String hexText = value.toString(16);

        while (hexText.length() < 32) 
            hexText = "0".concat(hexText);
        return hexText;
    }
    
    public static boolean verifyMessageHash(byte[] Message,String hashMessage) throws Exception{
        String message = new String(Message);
        if((hashString(message).compareTo(hashMessage)) == 0)
            return true;
        return false;   
    }


    //---------------------------Encryption/Decryption Functions----------------------------------


    public static byte[] encrypt(Key key, byte[] text) throws GeneralSecurityException {
        
        Cipher rsa;
        rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.ENCRYPT_MODE, key);
        return rsa.doFinal(text); 
    }

   
    public static String decrypt(byte[] keyBytes, byte[] buffer) throws GeneralSecurityException {
        
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
        Key key = keyFactory.generatePublic(keySpec);

        Cipher rsa;
        rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, key);
        byte[] value = rsa.doFinal(buffer);
        return new String(value);
    }

}