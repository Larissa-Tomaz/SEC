package sec.bftb.client;

import java.security.GeneralSecurityException;
import java.util.Scanner;

import javax.lang.model.util.ElementScanner6;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import sec.bftb.grpc.Contract.*;

import sec.bftb.client.Logger;

public class ClientMain {
	public static void main(String[] args) throws Exception {
		System.out.println(ClientMain.class.getSimpleName());
		Scanner myObj = new Scanner(System.in);

		Logger logger = new Logger("Client", "Main");

		// receive and print arguments
		System.out.printf("Received %d arguments%n", args.length);
		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}

		if (args.length != 3) {
			logger.log("Invalid Number of Arguments. Must be two: host base_port Max_Byzantine_Faults");
			myObj.close();
			return;
		} 

		final String host = args[0];
		final int base_port = Integer.parseInt(args[1]);
		final int maxByzantineFaults = Integer.parseInt(args[2]);
		int numberOfServers = 0;
		if(maxByzantineFaults <= 0){ //Probably change to only < 0 later 
			logger.log("Maximum number of byzantine faults tolerated must be greater than 0.");
			myObj.close();
			return;
		}
		numberOfServers = (maxByzantineFaults * 3) + 1; 
		final String target = host + ":" + base_port; //Delete later

		String[] command;
		String str;

		try{
			Client user = new Client(host, base_port, target, maxByzantineFaults, numberOfServers);//Delete target later

			System.out.println("Type 'help' to see avaliable operations.");

			while(myObj.hasNext()){
				System.out.print("> ");
				str = myObj.nextLine();
				command = str.split("\\s+");

				try{
					switch (command[0]) {
						case "open":
							if(command.length == 2)
								user.open(command[1]);
							else
								System.out.printf("Open command must have exactly 1 argument: Password.%n");
							break;
						case "send":
							if(command.length == 5)
								user.send(command[1], Integer.parseInt(command[2]), Integer.parseInt(command[3]),Float.parseFloat(command[4]));
							else
								System.out.printf("Send command must have exactly 4 arguments: Password senderUserID receiverUserID AmoutOfTransfer.%n");
							break;
						case "check":
							if(command.length == 3)
								user.check(command[1], Integer.parseInt(command[2]));
							else 
								System.out.printf("Check command must have exactly 2 arguments: Password UserID.%n");
							break;
						case "receive":
							if(command.length == 4)
								user.receive(command[1], Integer.parseInt(command[2]), Integer.parseInt(command[3]));
							else
								System.out.printf("Receive command must have exactly 3 arguments: Password UserID TransferId.%n");
							break;
						case "audit":
							if(command.length == 3)
								user.audit(command[1], Integer.parseInt(command[2]));
							else
								System.out.printf("Audit command must have exactly 2 arguments: Password UserID.%n");
							break;
						
						case "help":
							System.out.printf("Avaliable operations:\n");
							System.out.printf(" - open (1) -> open account \n");
							System.out.printf(" - send (1) (2) (3) (4) -> send (4) to user (3) from user (2) \n");
							System.out.printf(" - check (1) (2)-> check balance and pending movements of account (2) \n");
							System.out.printf(" - receive (1) (2) (3) -> approve movement (3) with account (2)  \n");
							System.out.printf(" - audit (1) (2) -> check balance and all movements of account (2) \n");
							System.out.printf(" - exit\n");
							break;
						case "exit":
							System.exit(0);
						default: 
							System.out.printf("That operation is unavailable.%n");
							break;
					}
				}catch(StatusRuntimeException e){
					if((e.getStatus().getCode().equals(Status.UNAVAILABLE.getCode()))){
						logger.log("Server unavailable at the moment.");
					}
					else if((e.getStatus().getCode().equals(Status.DEADLINE_EXCEEDED.getCode()))){
						logger.log("Time deadline for request excedeed. Request or Response may have been intentionally dropped.");
					}
					else
						logger.log(e.getStatus().getDescription());
				}catch(GeneralSecurityException e){
					logger.log("Invalid key pair");
				}catch(Exception ex){
					logger.log("Exceeeption with message: " + ex.getMessage() + " and cause:" + ex.getCause());
				} 	
			}
			myObj.close();

		}catch(Exception ex){
			logger.log("Exceeption with message: " + ex.getMessage() + " and cause:" + ex.getCause());
		}
	}
}