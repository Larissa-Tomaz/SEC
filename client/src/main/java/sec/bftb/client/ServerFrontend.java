package sec.bftb.client;


import java.util.concurrent.TimeUnit;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import sec.bftb.grpc.BFTBankingGrpc;
import sec.bftb.grpc.Contract.*;


public class ServerFrontend {
    private BFTBankingGrpc.BFTBankingBlockingStub stub;
    private final ManagedChannel channel;

    public ServerFrontend(String target) {
        channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
        stub = BFTBankingGrpc.newBlockingStub(channel);
    }

    public PingResponse ping(PingRequest request) { return stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).ping(request); }

    public void openAccount(openAccountRequest request) { stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).openAccount(request); }

    public sendAmountResponse sendAmount(sendAmountRequest request) { return stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).sendAmount(request); }

    public checkAccountResponse checkAccount(checkAccountRequest request) { return stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).checkAccount(request); }
    
    public receiveAmountResponse receiveAmount(receiveAmountRequest request) { return stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).receiveAmount(request); }

    public auditResponse audit(auditRequest request){ return stub.withDeadlineAfter(7000, TimeUnit.MILLISECONDS).audit(request); }
    
    public void close() {
        channel.shutdownNow();
    }
}
