package sec.bftb.server;

import io.grpc.Server;
import io.grpc.ServerBuilder;

import java.io.IOException;
import java.util.Scanner;

import sec.bftb.server.exceptions.ErrorMessage;
import sec.bftb.server.exceptions.ServerException;



public class ServerMain {

	static Logger logger;

	public static void main(String[] args){
		logger = new Logger("Server", "Main");
		logger.log("Starting server...");
		System.out.println(ServerMain.class.getSimpleName());
		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}
		

		if (args.length != 5) {
			logger.log("Invalid Number of Arguments. Must be five: basePort - serverPort - maxByzantineFaults - isByzantine(0=false) - clearDB(0=false)");
			System.exit(-1);
		}

		try {
			int basePort = Integer.parseInt(args[0]);
			int port = Integer.parseInt(args[1]);
			int maxByzantineFaults = Integer.parseInt(args[2]);
			boolean isByzantine = (Integer.parseInt(args[3]) != 0);
			boolean clearDB = (Integer.parseInt(args[4]) != 0);

			logger.log("Registering server port number: " + port);
			ServerServiceImpl serverService = new ServerServiceImpl(basePort, port, maxByzantineFaults, isByzantine, clearDB);
			Server server = ServerBuilder
					.forPort(port)
					.addService(serverService)
					.build()
					.start();

			// Server threads are running in the background.
			logger.log("Server started on port: " + port);

			new Thread(() -> {
				System.out.println("<Press enter to shutdown>");
				new Scanner(System.in).nextLine();
				server.shutdown();
				System.exit(0);
			}).start();

			server.awaitTermination();
			
		} catch (InterruptedException | IOException | ServerException e) {
			logger.log("Error on server start: " + e.getMessage());
		} catch (NumberFormatException e){
			logger.log("Invalid Type of Arguments. All must be integers: basePort - serverPort - maxByzantineFaults - isByzantine(0=false) - clearDB(0=false)");
		}
		
	}
}
