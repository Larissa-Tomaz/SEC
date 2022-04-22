package sec.bftb.server;


import io.grpc.stub.StreamObserver;
import sec.bftb.grpc.BFTBankingGrpc;
import sec.bftb.grpc.Contract.*;



public class DoubleEchoObserver<R> implements StreamObserver<R>{

    @Override
    public synchronized void onNext(R r) {
        /*if(r.getClass().getSimpleName().equals("echoResponse"))
            System.out.println("Received ECHO response");
        else if(r.getClass().getSimpleName().equals("readyResponse")){
            System.out.println("Received READY response");
        }*/
    }

    @Override
    public synchronized void onError(Throwable throwable) {
    }

    @Override
    public void onCompleted() {
    }
}

