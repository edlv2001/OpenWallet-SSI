import java.net.URI;

public interface Issuer {
    String giveVC(URI schema, String did, String jwtMockUp);

}
