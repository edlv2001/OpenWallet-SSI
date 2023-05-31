package es.edu.walletssi.key.exception;

public class IncorrectPasswordException extends RuntimeException{

    public IncorrectPasswordException(String msg){
        super(msg);
    }

    public IncorrectPasswordException(){
        this("Contraseña incorrecta.");
    }
}
