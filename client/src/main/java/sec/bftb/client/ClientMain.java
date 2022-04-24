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
			logger.log("Invalid Number of Arguments. Must be three: host base_port Max_Byzantine_Faults");
			myObj.close();
			return;
		} 

		final String host;
		final int base_port;
		final int maxByzantineFaults;
		try{
			host = args[0];
			base_port = Integer.parseInt(args[1]);
			maxByzantineFaults = Integer.parseInt(args[2]);
		} catch (NumberFormatException e){
			logger.log("Invalid Type of Arguments. (String) host (Integer) base_port (Integer) Max_Byzantine_Faults");
			myObj.close();
			return;
		}
		int numberOfServers = 0;
		if(maxByzantineFaults < 0){ 
			logger.log("Maximum number of byzantine faults tolerated must be greater than 0.");
			myObj.close();
			return;
		}
		numberOfServers = (maxByzantineFaults * 3) + 1; 

		String[] command;
		String str;

		try{
			Client user = new Client(host, base_port, maxByzantineFaults, numberOfServers);

			System.out.println("Type 'help' to see avaliable operations.");

			while(myObj.hasNext()){
				System.out.print("> ");
				str = myObj.nextLine();
				command = str.split("\\s+");

				try{
					switch (command[0]) {
						case "open":
							try{
								if(command.length == 2)
									user.open(command[1]);
								else
									System.out.printf("Open command must have exactly 1 argument: Password.%n");
							}catch (NumberFormatException e){
								logger.log("Invalid Type of arguments for open command. Must be String");
							}
							break;
						case "send":
							try{
								if(command.length == 5)
									user.send(command[1], Integer.parseInt(command[2]), Integer.parseInt(command[3]),Float.parseFloat(command[4]));
								else
									System.out.printf("Send command must have exactly 4 arguments: Password senderUserID receiverUserID AmoutOfTransfer.%n");
							}catch (NumberFormatException e){
								logger.log("Invalid Type of arguments for open command. Must be String Integer Integer Float");
							}
							break;
						case "check":
							try{
								if(command.length == 4)
									user.check(command[1], Integer.parseInt(command[2]), Integer.parseInt(command[3]));
								else 
									System.out.printf("Check command must have exactly 2 arguments: Password UserID UserID_of_Account_to_Check.%n");
							}catch (NumberFormatException e){
								logger.log("Invalid Type of arguments for open command. Must be String Integer Integer");
							}
							break;
						case "receive":
							try{
								if(command.length == 4)
									user.receive(command[1], Integer.parseInt(command[2]), Integer.parseInt(command[3]));
								else
									System.out.printf("Receive command must have exactly 3 arguments: Password UserID TransferId.%n");
							}catch (NumberFormatException e){
								logger.log("Invalid Type of arguments for open command. Must be String Integer Integer");
							}
							break;
						case "audit":
							try{
								if(command.length == 2)
									user.audit(Integer.parseInt(command[1]));
								else
									System.out.printf("Audit command must have exactly 1 argument: UserID.%n");
							}catch (NumberFormatException e){
								logger.log("Invalid Type of arguments for open command. Must be Integer");
							}
							break;
						case "byzantine":
							if(command.length == 1)
								user.changeIsByzantine();
							else
								System.out.printf("Change Byzantine Flag command must have exactly 0 arguments.%n");
							break;
						
						case "help":
							System.out.printf("Avaliable operations:\n");
							System.out.printf(" - open (1) -> open account \n");
							System.out.printf(" - send (1) (2) (3) (4) -> send (4) to user (3) from user (2) \n");
							System.out.printf(" - check (1) (2) (3)-> check balance and pending movements of account (3) using keys associated with account(2)\n");
							System.out.printf(" - receive (1) (2) (3) -> approve movement (3) with account (2)  \n");
							System.out.printf(" - audit (1) -> check balance and all movements of account (1) \n");
							System.out.printf(" - byzantine -> change byzantine flag of client (initially = false) \n");
							System.out.printf(" - exit\n");
							break;
						case "exit":
							System.exit(0);
						default: 
							System.out.printf("That operation is unavailable.%n");
							break;
					}
				}
				catch(Exception ex){
					if(!ex.getMessage().equals("maxCrashFaults"))
						logger.log("Exception with message: " + ex.getMessage());
					else
						logger.log("More than " + maxByzantineFaults + " server(s) were unresponsive. Please repeat the request...");
				} 	
			}
			myObj.close();

		}catch(Exception ex){
			logger.log("Exception with message: " + ex.getMessage());
		}
	}
}