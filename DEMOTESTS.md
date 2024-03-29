# TESTS

Before all tests, do the following:

Start by creating two accounts, using the **open** command, assigning a password to each one, saving both ids and the generated passwords. Use the first one as sender and the second as receiver
```shell
open [password_sender]
open [password_receiver]
```
### NORMAL RUN TEST

Use the ids created before and the passwords and confirm that the accounts have been created and their balance is 50.0 (initial balance established), using the **check** command
```shell
check [password_verifier] [verifier_id] [sender_id]
check [password_verifier] [verifier_id] [sender_id]
```
Now, send 25.0 from the sender to the receiver, using the **send** command
```shell
send [password_sender] [sender_id] [receiver_id] 25
```
Confirm that the money has been removed from the sender, using the **check** command
```shell
check [password_verifier] [verifier_id] [sender_id]
```
Now, use the **check** command to see the Pending movements for the receiver. Save the movement id
```shell
check [password_verifier] [verifier_id] [receiver_id]
```
Accept the movement, using the **receive** command and the movement id previously saved. Then, see if the balance has changed
```shell
receive [password_receiver] [receiver_id] [movement_id]
check [password_verifier] [verifier_id] [receiver_id]
```
To see all confirmed/rejected movements related to an account, use the **audit** command
```shell
audit [receiver_id]
```

### WRONG KEY TEST
Try to send money to an account using a wrong id
```shell
send [password] [wrong_id] [receive_id] 13
```

### NO MONEY TEST
After creating the accounts, confirm the balance of the sender
```shell
check [password_verifier] [verifier_id] [sender_id]
```
Try to send to the receiver more money than the sender has in its account
```shell
send [password_sender] [sender_id] [receiver_id] 60
```

### NO MOVEMENT TEST
Start by confirming both accounts exist and have no pending movements
```shell
check [password_verifier] [verifier_id] [sender_id]
check [password_verifier] [verifier_id] [receiver_id]
```
Try to accept a movement, using the **receive** command. 
```shell
receive [password_receiver] [receiver_id] 1000
```

### MOVEMENT ALREADY ACCEPTED TEST
Start by confirming both accounts exist and have no pending movements
```shell
check [password_verifier] [verifier_id] [sender_id]
check [password_verifier] [verifier_id] [receiver_id]
```
Now, send 25.0 from the sender to the receiver, using the **send** command
```shell
send [password_sender] [sender_id] [receiver_id] 25
```

Confirm, using the **check** command, that the receiver has a pending movement. Save the movement id
```shell
check [password_verifier] [verifier_id] [receiver_id]
```
Accept the movement, using the **receive** command and the id previously saved. Then, see if the balance has changed, and if the list of pending movements is empty
```shell
receive [password_receiver] [receiver_id] [movement_id]
check [password_verifier] [verifier_id] [receiver_id]
```
Try to receive the movement again
```shell
receive [password_receiver] [receiver_id] [movement_id]
```
Finally audit both accounts to obtain the full transaction history of both
```shell
audit [sender_id]
audit [receiver_id]
```

### 1 BYZANTINE SERVER TEST
Assuming the rule 3f+1 servers to tolerate f byzantine server, first you can start 4 servers with one of them being byzantine.
Each one of this commands should be run in a different process at the server directory.
```shell
mvn exec:java -Dexec.args="8090 8090 1 0 0"
mvn exec:java -Dexec.args="8090 8091 1 0 0"
mvn exec:java -Dexec.args="8090 8092 1 0 0"
mvn exec:java -Dexec.args="8090 8093 1 1 0"
```
Now, you can use any one of the tests above. we suggest you use the NORMAL RUN TEST

### MANY BYZANTINE SERVERS
For this, you can start 4 servers, 2 of them being byzantine.
Each one of this commands should be run in a different process at the server directory.
```shell
mvn exec:java -Dexec.args="8090 8090 1 0 0"
mvn exec:java -Dexec.args="8090 8091 1 0 0"
mvn exec:java -Dexec.args="8090 8092 1 1 0"
mvn exec:java -Dexec.args="8090 8093 1 1 0"
```
Now, you can use any one of the tests above. we suggest you use the NORMAL RUN TEST

### BYZANTINE CLIENT
Start a client as usual, create an account and perform any command that writes in the system, for example you can perform an send amount command.
```shell
send [password_sender] [sender_id] [receiver_id] 5
```
Check if the changes were saved
```shell
check [password_sender] [sender_id]
```
Then, use the following command to transform the client into a byzantine client
```shell
byzantine
```
Then, perform the same command
```shell
send [password_sender] [sender_id] [receiver_id] 5
```
Notice how the servers refuse to execute the client's command.
Perform an audit command to see how nothing has changed.
```shell
audit [sender_id]
```