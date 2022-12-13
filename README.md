## Java Backdoor

### Backdoor feito a partir da linguagem java
<hr>

#### Funciona a base de um arquivo de para o Servidor que será rodado na local de ataque e um arquivo para o Cliente, que será a base da conexão com o backdoor

#### É composto de por um envio de mensagens criptografadas com o algoritimo RSA, e veracidade de hash com o algoritimo SHA3-256
#### Funciona de forma Multi-Threading, permitindo várias conexões simultaneamente
#### Qualquer mensagem enviada pelo cliente para o servidor será interpretada e executada no bash do diretório do servidor e será retornado a resposta do "comando" para o cliente

### 📨 Versões
- JDK-19
- Maven 1.9

### 💻 Como usar

- Primeiro é necessário clonar este repositorio: <br>
``` git clone https://PatrickLeonardo/java-backdoor ```

- Após isso basta navegar até a pasta principal: <br>
``` cd java-backdoor/src/main/java/backdoor/java ```

- Em seguida rodar o servidor com: <br>
``` java Server.java ```

- E rodar um cliente e um terminal diferente: <br>
``` java Client.java <IP-DO-SERVIDOR> 1234 ```

### Observações

O backdoor tambem pode ser usado apenas com os arquivos do servidor e cliente, mas devem ser apenas rodados com a pasta [keystore](https://github.com/PatrickLeonardo/java-backdoor/tree/main/src/main/java/backdoor/java/keystore) no mesmo diretorio. <br>
Feito para ser usado em testes de pentração (pentest) e pós-exploração em servidores rodados com basse em java, como J2EE, ReadHat JBoss EAP, Jetty e etc...
