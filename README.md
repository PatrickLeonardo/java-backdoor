## Java Backdoor

### Backdoor feito a partir da linguagem java
<hr>

#### Funciona a base de um arquivo para o [Servidor](https://github.com/PatrickLeonardo/java-backdoor/tree/main/src/main/java/backdoor/java/Server.java) que será rodado na local de ataque e um arquivo para o [Cliente](https://github.com/PatrickLeonardo/java-backdoor/tree/main/src/main/java/backdoor/java/Client.java), que será a base da conexão com o backdoor

#### É composto por um envio de mensagens criptografadas com o algoritimo RSA, e veracidade de hash com o algoritimo SHA3-256
#### Funciona de forma Multi-Threading, permitindo várias conexões simultaneamente (as mensagens possuem um limite de tamanho de 245 bytes)
#### Qualquer mensagem enviada pelo cliente para o servidor será interpretada e executada no bash do diretório do servidor e será retornado a resposta do "comando" para o cliente
#### Possui suporte aos sistemas operacionais Windows e distribuições Linux

### 📨 Versões
- JDK-19
- Maven 1.9

### 💻 Como usar

- Primeiro é necessário clonar este repositrio: <br>
``` git clone https://github.com/PatrickLeonardo/java-backdoor ```

- Após isso basta navegar até a pasta principal: <br>
``` cd java-backdoor/src/main/java/backdoor/java ```

- Em seguida rodar o servidor com: <br>
``` java Server.java <OS>```

- E rodar um cliente e um terminal diferente: <br>
``` java Client.java <IP-DO-SERVIDOR> 1234 ```

### Observações

O backdoor também pode ser usado apenas com os arquivos do servidor e cliente, mas devem ser apenas rodados com a pasta [keystore](https://github.com/PatrickLeonardo/java-backdoor/tree/main/src/main/java/backdoor/java/keystore) no mesmo diretorio. <br>
Feito para ser usado em testes de penetração (pentest) e pós-exploração em servidores rodados com base em java, como J2EE, ReadHat JBoss EAP, Jetty e etc...
