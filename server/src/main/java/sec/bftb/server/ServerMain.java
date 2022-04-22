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
		

		if (args.length != 1) {
			logger.log("Failed to start server. Number of initial arguments is not supported: " + args.length);
			System.exit(-1);
		}

		try {
			int port = Integer.parseInt(args[0]);
			logger.log("Registering server port number: " + port);
			ServerServiceImpl serverService = new ServerServiceImpl(port);
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
		}
		
	}
}
