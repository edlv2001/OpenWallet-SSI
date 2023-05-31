import org.example.walletssi.Wallet;
import org.example.walletssi.init.WalletConfiguration;
import org.example.walletssi.key.KeyType;
import org.example.walletssi.key.exception.IncorrectPasswordException;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;

import java.security.KeyPair;

public class Verifier {

    private Wallet wallet;

    private String name;

    public Verifier(String name, String globalPath){
        this.name = name;
        WalletConfiguration configuration = new WalletConfiguration(
                DidMethod.KEY,
                new DefaultMethodHandlerConfig(globalPath + "/dids"),
                globalPath + "/keys",
                globalPath + "/vcOwned",
                globalPath + "/vcStore",
                globalPath + "/vpStore"
        );
        wallet = new Wallet(configuration);
    }


    public boolean askForVC(Holder holder){
        String vp = holder.givePresentation("https://schema.affinidi.com/CreditScoreV1-0.json");
        return wallet.verifyVP(vp, false);
    }
}
