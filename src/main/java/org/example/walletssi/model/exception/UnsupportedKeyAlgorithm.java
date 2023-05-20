package org.example.walletssi.model.exception;

public class UnsupportedKeyAlgorithm extends RuntimeException {
    private String message;
    public UnsupportedKeyAlgorithm(String s) {
        super();
        this.message = s;
    }
    @Override
    public String getMessage() {
        return super.getMessage() + message;
    }
}
