import es.edu.walletssi.Wallet;
import es.edu.walletssi.init.WalletConfiguration;
import es.edu.walletssi.key.KeyType;
import es.edu.walletssi.key.exception.IncorrectPasswordException;
import es.edu.walletssi.model.DidMethod;
import es.edu.walletssi.model.handlers.config.DefaultMethodHandlerConfig;

import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.List;

public class Holder {

    private Wallet wallet;
    private String did;

    public Holder(String globalPath){
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

        List<String> l = wallet.listDIDs();
        if(l.size()> 0){
            did = l.get(0);
            System.out.println("El Holder ha obtenido su DID " + did);
        }
        else {
            did = wallet.genDID(kp.getPublic());
            System.out.println("El Holder ha generado el DID \""  + did + "\".");
        }
    }

    public String getDid() {
        return did;
    }

    public void storeVC(String vc){
        wallet.storeVC(vc);
    }

    public String givePresentation(URI schema){
        System.out.println("El usuario concede acceso a la credencial, y genera la presentación");
        List<String> l = wallet.listOwnedVc(schema);
        return wallet.issueVP(
                wallet.getOwnedVC(l.get(l.size()-1)),
                did,
                wallet.getKeys("key1", "1234", KeyType.RSA),
                Date.from(Instant.now()),
                false
        );
    }

    public void askForID(Issuer issuer){
        System.out.println("Usuario utiliza teléfono hasta que requiere una credencial de tipo DNI");
        System.out.println("El usuario encuentra el schema de la credencial y hace la petición al CNP");
        URI schema = URI.create("https://schema.affinidi.com/IDReducedV1-0.json");
        String vc = issuer.giveVC(schema, did, null);

        System.out.println("El usuario, ahora Holder, ha recibido su credencial DNI:\n\n" + vc);
        if(wallet.verifyVC(vc,false)){
            System.out.println("La credencial es auténtica");
            wallet.storeVC(vc);
        } else {
            System.out.println("La credencial no es auténtica");
        }

    }

    public void askForCreditScore(Issuer issuer){
        System.out.println("\n\n\nEl Holder ahora requiere una credencial de Scoring bancario," +
                "\nen lugar de iniciar sesión como normalmente lo hacía, concede acceso a su credencial DNI");
        URI schema = URI.create("https://schema.affinidi.com/CreditScoreV1-0.json");
        URI idSchema = URI.create("https://schema.affinidi.com/IDReducedV1-0.json");
        List<String> list = wallet.listOwnedVc(idSchema);
        if(list.size() == 0) return;
        String vcId = wallet.getOwnedVC(list.get(list.size()-1));
        String vp = wallet.issueVP(
                vcId,
                did,
                wallet.getKeys("key1", "1234", KeyType.RSA),
                Date.from(Instant.now()),
                true
                );
        System.out.println("Usuario pide la credencial, enviando para eso la presentación de su DNI");

        String vc = issuer.giveVC(schema, did, vp);

        System.out.println("\n\nCredencial de Scoring recibida:\n" + vp);
        if(wallet.verifyVC(vc,false)){
            System.out.println("La credencial es auténtica");
            wallet.storeVC(vc);
        } else {
            System.out.println("La credencial no es auténtica");
        }
    }
}
