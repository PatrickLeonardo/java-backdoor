## Java Backdoor

### Backdoor made with java
<hr>

#### It works based on a file for the [Server](https://github.com/PatrickLeonardo/java-backdoor/tree/main/src/main/java/backdoor/java/Server.java) that will be run at the attack site and a file for the [Client](https://github.com/PatrickLeonardo/java-backdoor/tree/main/src/main/java/backdoor/java/Client.java), which will be the basis for the connection with the backdoor

#### It consists of sending encrypted messages with the RSA algorithm, and hash veracity with the SHA3-256 algorithm
#### It works in a Multi-Threading manner, allowing multiple connections simultaneously (messages have a size limit of 245 bytes)
#### Any message sent by the client to the server will be interpreted and executed in the bash directory of the server and the response of the "command" will be returned to the client
#### Supports Windows operating systems and Linux distributions

### 📨 Versions
- JDK-19
- Maven 1.9

### 💻 How to use

- First you need to clone this repository: <br>
``` git clone https://github.com/PatrickLeonardo/java-backdoor ```

- After that, just navigate to the main folder: <br>
``` cd java-backdoor/src/main/java/backdoor/java ```

- Then run the server with: <br>
``` java Server.java <OS>```

- And run the client in a different terminal: <br>
``` java Client.java <SERVER-IP> 1234 ```

### Notes

The backdoor can also be used with just the server and client files, but they must only be run with the [keystore](https://github.com/PatrickLeonardo/java-backdoor/tree/main/src/main/java/backdoor/java/keystore) folder in the same directory. <br>
Made to be used in penetration testing (pentest) and post-exploitation on servers running on Java, such as J2EE, ReadHat JBoss EAP, Jetty, and more...
