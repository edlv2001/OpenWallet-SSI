import es.edu.walletssi.Wallet;
import es.edu.walletssi.init.WalletConfiguration;
import es.edu.walletssi.model.DidMethod;
import es.edu.walletssi.model.handlers.config.DefaultMethodHandlerConfig;

import java.net.URI;

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


    public void askForVC(Holder holder){
        String vp = holder.givePresentation(URI.create("https://schema.affinidi.com/CreditScoreV1-0.json"));
        System.out.println(name + " ha obtenido la presentacion verificable: \n" + vp);
        if(wallet.verifyVPWithOnlyVCSchema(vp, false)){
            System.out.println(name + " ha verificado que la presentacion es auténtica");
        } else {
            System.out.println(name + " ha verificado que la presentacion no es auténtica");
        }
    }
}
