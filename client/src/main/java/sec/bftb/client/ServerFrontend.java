package sec.bftb.client;


import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import sec.bftb.grpc.BFTBankingGrpc;
import sec.bftb.grpc.Contract.*;


public class ServerFrontend {
    private BFTBankingGrpc.BFTBankingStub stub;
    private final ManagedChannel channel;

    public ServerFrontend(String target) {
        channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
        stub = BFTBankingGrpc.newStub(channel);
    }

    //public PingResponse ping(PingRequest request) { return stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).ping(request); }

    public void openAccount(openAccountRequest request, ServerObserver<openAccountResponse> serverObs) { stub.withDeadlineAfter(5000, TimeUnit.MILLISECONDS).openAccount(request,serverObs); }

    public void sendAmount(sendAmountRequest request, ServerObserver<sendAmountResponse> serverObs) { stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).sendAmount(request,serverObs); }

    public void checkAccount(checkAccountRequest request, ServerObserver<checkAccountResponse> serverObs) { stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).checkAccount(request,serverObs); }
    
    public void receiveAmount(receiveAmountRequest request, ServerObserver<receiveAmountResponse> serverObs) { stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).receiveAmount(request,serverObs); }

    public void audit(auditRequest request, ServerObserver<auditResponse> serverObs){ stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).audit(request,serverObs); }
    
    public void getHighestRegisterSequenceNumber(highestRegisterSequenceNumberRequest request, ServerObserver<highestRegisterSequenceNumberResponse> serverObs){
        stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).getHighestRegisterSequenceNumber(request,serverObs);
    }
    
    public void close() {
        channel.shutdownNow();
    }
}
