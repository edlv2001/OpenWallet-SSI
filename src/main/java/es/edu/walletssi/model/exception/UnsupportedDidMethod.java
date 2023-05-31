package es.edu.walletssi.model.exception;

public class UnsupportedDidMethod extends RuntimeException {
    private String message;
    public UnsupportedDidMethod(String s) {
        super();
        this.message = s;
    }
    @Override
    public String getMessage() {
        return super.getMessage() + message;
    }
}
