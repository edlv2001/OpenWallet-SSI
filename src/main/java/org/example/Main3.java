package org.example;

import org.checkerframework.checker.units.qual.K;
import org.example.walletssi.Wallet;
import org.example.walletssi.init.WalletConfiguration;
import org.example.walletssi.key.KeyType;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.handlers.config.DefaultMethodHandlerConfig;
import org.example.walletssi.model.handlers.config.EBSIMethodHandlerConfig;

import java.net.URI;
import java.security.KeyPair;
import java.sql.Date;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public class Main3 {

    public static void main(String[] args) {
        WalletConfiguration configuration = new WalletConfiguration(
                DidMethod.EBSI,
                new EBSIMethodHandlerConfig(null, null, null),
                null,
                null,
                null,
                null
        );

        Wallet w1 = new Wallet(configuration);

        String alias = "example";
        //KeyPair kp = w1.getKeys(alias, "newPassword", KeyType.ED25519);

        //String mnemonic = w1.genKey(alias + alias, "newPassword", KeyType.RSA);
        KeyPair kp = w1.getKeys(alias + alias, "newPassword", KeyType.RSA);
        //String mnemonic = w1.genKey(alias + "xd", "p", KeyType.RSA);
        //System.out.println(w1.recoverPassword(alias + "xd", "newPassword2", mnemonic, KeyType.RSA));
        List<String> dids = w1.listDIDs();

        String did1 = dids.get(2);

        //did1 = w1.genDID(kp.getPublic());



        Map<String, Object> claims = Map.of("name", "Eduardo", "familyName", "de la Vega", "creditScore", 500);
        //String vc = w1.issueVC(claims, did1, kp, did1, Date.from(Instant.now().plusSeconds(3600)));

        String vc = w1.issueVC(URI.create("https://schema.affinidi.com/CreditScoreV1-0.json"), "CreditScore", claims, did1, kp, did1, Date.from(Instant.now().plusSeconds(3600)), true);
        System.out.println(vc);


        WalletConfiguration walletConfiguration = new WalletConfiguration(
                DidMethod.KEY,
                new EBSIMethodHandlerConfig(null, null, null),
                null,
                null,
                null,
                null
        );
        Wallet w2 = new Wallet(walletConfiguration);

        //System.out.println("HOLAAAAAAAAAAA " + w2.verifyVC(vc, false));
        w2.verifyVC(vc, false);


        //w2.genKey(alias, "newPassword", KeyType.ED25519);
        KeyPair kp2 = w2.getKeys(alias, "newPassword", KeyType.ED25519);

        String did2;
        did2 = w2.listDIDs().get(0);
        //did2 = w2.listDIDs().get(0);

        String vp;
        //System.out.println(vp = w2.issueVP(vc, did2, kp2, Date.from(Instant.now().plusSeconds(3600)), true));
        vp = w2.issueVP(vc, did2, kp2, Date.from(Instant.now().plusSeconds(3600)), true);

        System.out.println(w1.verifyVP(vp, false));

        System.out.println(w1.verifyVPWithoutRegistry(vp));

        System.out.println(w1.verifyVPWithOnlyVCSchema(vp, false));



        List<String> list = w1.listCreatedVc();

        /*for(String s : list){
            System.out.println(s);
            System.out.println(w1.getCreatedVC(s));

        }*/

    }

}
