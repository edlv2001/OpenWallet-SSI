import com.danubetech.verifiablecredentials.VerifiablePresentation;
import es.edu.walletssi.Wallet;
import es.edu.walletssi.init.WalletConfiguration;
import es.edu.walletssi.key.KeyType;
import es.edu.walletssi.key.exception.IncorrectPasswordException;
import es.edu.walletssi.model.DidMethod;
import es.edu.walletssi.model.handlers.config.EBSIMethodHandlerConfig;

import java.net.URI;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class IssuerBank implements Issuer{

    private Wallet wallet;

    private String name;

    private String did;

    private KeyPair kp;

    public IssuerBank(String name, String globalPath){
        this.name = name;
        WalletConfiguration configuration = new WalletConfiguration(
                DidMethod.EBSI,
                new EBSIMethodHandlerConfig(globalPath + "/dids", null, null),
                globalPath + "/keys",
                globalPath + "/vcOwned",
                globalPath + "/vcStore",
                globalPath + "/vpStore"
        );
        wallet = new Wallet(configuration);
        try{
            kp = wallet.getKeys("key1", "1234", KeyType.ED25519);
            if(kp == null) {
                wallet.genKey("key1", "1234", KeyType.ED25519);
                kp = wallet.getKeys("key1", "1234", KeyType.ED25519);
            }
        } catch (IncorrectPasswordException e){
            throw new RuntimeException("Clave ya existente y con otra contraseña");

        }
        List<String> l = wallet.listDIDs();
        if(l.size()> 0){
            did = l.get(0);
        }
        else {
            did = wallet.genDID(kp.getPublic());
        }
        System.out.println("El issuer " + name + " ha generado el DID \""  + did + "\".");
    }

    public String issueCreditScore(String vpID, String didHolder){
        VerifiablePresentation vp = VerifiablePresentation.fromJson(vpID);
        if(!vp.getHolder().toString().equals(didHolder) ||
                !vp.getVerifiableCredential().getCredentialSubject().getId().toString().equals(didHolder)){
            return null;
        }
        Map<String, Object> claims = vp.getVerifiableCredential().getCredentialSubject().getClaims();
        claims.put("creditScore", searchScoreMockUp());
        return wallet.issueVC(URI.create("https://schema.affinidi.com/CreditScoreV1-0.json"), "Credit Score",claims, did, kp, didHolder, Date.from(Instant.now().plusSeconds(7200)), false);
    }

    private int searchScoreMockUp(){
        return  (int)(Math.random() * 550 + 300);
    }


    public String giveVC(URI schema, String did, String loginVC){
        //LOGIN
        if(loginVC == null || !wallet.verifyVPWithOnlyVCSchema(loginVC, false)) return null;

        //ISSUANCE FROM AVAILABLE SCHEMAS
        if(schema.toString().equals("https://schema.affinidi.com/CreditScoreV1-0.json"))
            return issueCreditScore(loginVC,did);
        return null;
    }



}
