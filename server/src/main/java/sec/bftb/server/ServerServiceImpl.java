package sec.bftb.server;

import io.grpc.stub.StreamObserver;

import java.io.IOException;
import sec.bftb.grpc.Contract.*;
import sec.bftb.server.exceptions.ServerException;
import sec.bftb.grpc.BFTBankingGrpc;

import static io.grpc.Status.INVALID_ARGUMENT;


public class ServerServiceImpl extends BFTBankingGrpc.BFTBankingImplBase {
    
	private final Server server;
    private final int serverPort;
    private final Logger logger;

	public ServerServiceImpl(int serverPort) throws IOException, ServerException{
        this.server = new Server(serverPort);
        this.serverPort = serverPort;
        this.logger = new Logger("Server", "Service");
    }


	@Override
	public void ping(PingRequest request, StreamObserver<PingResponse> responseObserver) {
			PingResponse response = PingResponse.newBuilder().
					setOutputText(server.ping()).build();
			responseObserver.onNext(response);
			responseObserver.onCompleted();
	}


	@Override
	public void openAccount(openAccountRequest request, StreamObserver<openAccountResponse> responseObserver) {
		try{
			logger.log("Received openAccountRequest");
			openAccountResponse response = server.open_account(request.getPublicKeyClient(),request.getRegisterSignature(),
			request.getSequenceNumber(), request.getHashMessage());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void sendAmount(sendAmountRequest request, StreamObserver<sendAmountResponse> responseObserver) {
		try{
			sendAmountResponse response = server.send_amount(request.getPublicKeySender(), request.getPublicKeyReceiver(), 
			request.getAmount(), request.getSequenceNumber(), request.getHashMessage());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void checkAccount(checkAccountRequest request, StreamObserver<checkAccountResponse> responseObserver) {
		try{
			checkAccountResponse response = server.check_account(request.getPublicKeyClient(),request.getSequenceNumber());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void receiveAmount(receiveAmountRequest request, StreamObserver<receiveAmountResponse> responseObserver) {
		try{
			receiveAmountResponse response = server.receive_amount(request.getPublicKeyClient(), 
			request.getMovementId(), request.getSequenceNumber(), request.getHashMessage());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	
	@Override
	public void audit(auditRequest request, StreamObserver<auditResponse> responseObserver) {
		try{
			auditResponse response = server.audit(request.getPublicKeyClient(),
			request.getSequenceNumber(), request.getHashMessage());
			responseObserver.onNext(response);
			responseObserver.onCompleted();	
		}
		catch (Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}

	@Override
	public void getHighestRegisterSequenceNumber(highestRegisterSequenceNumberRequest request, StreamObserver<highestRegisterSequenceNumberResponse> responseObserver ){
		try{
			highestRegisterSequenceNumberResponse response = server.getHighestSeq(request.getPublicKey(), request.getSequenceNumber(), request.getHashMessage());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch(Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


	@Override
	public void writeBack(writeBackRequest request, StreamObserver<writeBackResponse> responseObserver) {
		try{
			writeBackResponse response = server.writeBack(request.getPublicKey(), request.getRegisterSequenceNumber(),
				request.getRegisterSignature(), request.getBalance(), request.getMessageSequenceNumber(), request.getHashMessage());
			responseObserver.onNext(response);
			responseObserver.onCompleted();
		}
		catch(Exception e){
			responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
		}
	}


}