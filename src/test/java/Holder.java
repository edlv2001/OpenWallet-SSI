import org.example.walletssi.Wallet;
import org.example.walletssi.init.WalletConfiguration;
import org.example.walletssi.key.KeyType;
import org.example.walletssi.key.exception.IncorrectPasswordException;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public class Holder {

    private Wallet wallet;

    private String name;

    private String did;

    public Holder(String name, String globalPath){
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
        KeyPair kp;
        try{
            kp = wallet.getKeys("key1", "1234", KeyType.RSA);
            if(kp == null){
                wallet.genKey("key1","1234", KeyType.RSA);
                kp = wallet.getKeys("key1", "1234", KeyType.RSA);
            }
        } catch (IncorrectPasswordException e){
            throw new RuntimeException("Clave ya existente y con otra contraseña");
        }

        did = wallet.genDID(kp.getPublic());

    }

    public String getDid() {
        return did;
    }

    public void storeVC(String vc){
        wallet.storeVC(vc);
    }

    public String givePresentation(String schema){
        return wallet.issueVP(
                wallet.listOwnedVc(schema).get(0),
                did,
                wallet.getKeys("key1", "1234", KeyType.RSA),
                Date.from(Instant.now()),
                false
        );
    }

    public void askForID(Issuer issuer){
        String schema = "https://schema.affinidi.com/IDReducedV1-0.json";
        String vc = issuer.giveVC(schema, did, null);

    }

    public void askForCreditScore(Issuer issuer){
        String schema = "https://schema.affinidi.com/CreditScoreV1-0.json";
        String idSchema = "https://schema.affinidi.com/IDReducedV1-0.json";
        List<String> list = wallet.listOwnedVc(idSchema);
        if(list.size() == 0) return;
        String vcId = list.get(0);
        wallet.issueVP(
                vcId,
                did,
                wallet.getKeys("key1", "1234", KeyType.RSA),
                Date.from(Instant.now()),
                true
                );
        String vc = issuer.giveVC(schema, did, vcId);
        wallet.storeVC(vc);
    }
}
