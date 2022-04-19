package sec.bftb.client;

import java.util.ArrayList;
import io.grpc.stub.StreamObserver;
import sec.bftb.grpc.BFTBankingGrpc;
import sec.bftb.grpc.Contract.*;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;


public class ServerObserver<R> implements StreamObserver<R>{

    private ArrayList<R> responses = new ArrayList<>();
    private ArrayList<StatusRuntimeException> exceptions = new ArrayList<>();

    public ArrayList<R> getResponseCollector(){
        return responses;
    }

    public ArrayList<StatusRuntimeException> getExceptionCollector(){
        return exceptions;
    }

    @Override
    public synchronized void onNext(R r) {
        responses.add(r);
        System.out.println("Received " + r.getClass().getSimpleName());  
        this.notifyAll();
        return;
    }


    @Override
    public synchronized void onError(Throwable throwable) {
        if(throwable instanceof StatusRuntimeException){
            StatusRuntimeException e = (StatusRuntimeException) throwable;
            /*if(Status.DEADLINE_EXCEEDED.getCode() == e.getStatus().getCode()){
                System.out.println("The deadline for this request is already over: " + e.getStatus().getDescription());
                //this.notifyAll();
            }   

            else if(Status.INVALID_ARGUMENT == e.getStatus()){
                System.out.println("The request is wrongly formatted.");
            }
                
            else if(Status.CANCELLED.getCode() == e.getStatus().getCode())
                System.out.println("This request was cancelled.");   
                
            else if(Status.UNAVAILABLE.getCode() == e.getStatus().getCode())
                System.out.println("This channel was forcedly shutdown because the response is no longer needed.");  

            else
                System.out.println("Error ocurred with description: " + e.getStatus().getDescription());
            */
            exceptions.add(e);
            this.notifyAll();
        }
    }

    @Override
    public void onCompleted() {
        System.out.println("Request completed");
    }
}
