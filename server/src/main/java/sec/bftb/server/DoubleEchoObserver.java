package sec.bftb.server;


import io.grpc.stub.StreamObserver;
import sec.bftb.grpc.BFTBankingGrpc;
import sec.bftb.grpc.Contract.*;



public class DoubleEchoObserver<R> implements StreamObserver<R>{

    @Override
    public synchronized void onNext(R r) {
    }

    @Override
    public synchronized void onError(Throwable throwable) {
    }

    @Override
    public void onCompleted() {
    }
}

