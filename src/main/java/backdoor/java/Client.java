package backdoor.java;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class Client {

    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        
        final int PORT = Integer.parseInt(args[0]);

        Socket client = new Socket("localhost", PORT);
        
        try{

            ObjectInputStream entrada = new ObjectInputStream(client.getInputStream());
            ObjectOutputStream exit = new ObjectOutputStream(client.getOutputStream());                

            String mensagem = (String)entrada.readObject();
            System.out.println(mensagem);
            
            while(client.isConnected()){
                
                String msg = System.console().readLine("$ ");
                exit.writeObject(msg);

                if("exit".equals(msg)){
                    exit.flush();
                    exit.close(); 
                    client.close();
                    break; }
                
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
