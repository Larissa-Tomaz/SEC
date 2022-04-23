package sec.bftb.client;

import java.util.ArrayList;
import io.grpc.stub.StreamObserver;
import sec.bftb.grpc.BFTBankingGrpc;
import sec.bftb.grpc.Contract.*;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;


public class ServerObserver<R> implements StreamObserver<R>{

    private ArrayList<R> responses = new ArrayList<>();
    private ArrayList<StatusRuntimeException> logicExceptions = new ArrayList<>();
    private ArrayList<Exception> systemExceptions = new ArrayList<>();

    public ArrayList<R> getResponseCollector(){
        return responses;
    }

    public ArrayList<StatusRuntimeException> getLogicExceptionCollector(){
        return logicExceptions;
    }

    public ArrayList<Exception> getSystemExceptionCollector(){
        return systemExceptions;
    }


    @Override
    public synchronized void onNext(R r) {
        responses.add(r);
        this.notifyAll();
        return;
    }


    @Override
    public synchronized void onError(Throwable throwable) {
        if(throwable instanceof StatusRuntimeException){
            StatusRuntimeException e = (StatusRuntimeException) throwable;

            if(Status.INVALID_ARGUMENT.getCode() == e.getStatus().getCode()){
                logicExceptions.add(e);
                this.notifyAll();
                return;
            }
        }
        systemExceptions.add((Exception)throwable);
        this.notifyAll();
    }

    @Override
    public void onCompleted() {
    }
}
