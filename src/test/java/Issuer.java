import com.danubetech.verifiablecredentials.VerifiablePresentation;
import org.example.walletssi.Wallet;
import org.example.walletssi.init.WalletConfiguration;
import org.example.walletssi.key.KeyType;
import org.example.walletssi.key.exception.IncorrectPasswordException;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.handlers.config.EBSIMethodHandlerConfig;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

public interface Issuer {
    String giveVC(String schema, String did, String jwtMockUp);

}
