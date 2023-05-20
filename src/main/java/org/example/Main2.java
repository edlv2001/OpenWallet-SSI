package org.example;

import com.google.crypto.tink.subtle.Hex;
import org.example.walletssi.Wallet;
import org.example.walletssi.init.WalletConfiguration;
import org.example.walletssi.key.KeyHandlerEd25519;
import org.example.walletssi.key.exception.IncorrectPasswordException;
import org.example.walletssi.model.DidMethod;
import org.example.walletssi.model.handlers.config.EBSIMethodHandlerConfig;

import java.security.KeyPair;
import java.sql.Date;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

public class Main2 {
    public static void main(String[] args){
        String alias = "example";


        WalletConfiguration walletConfiguration = new WalletConfiguration(
                DidMethod.EBSI,
                new EBSIMethodHandlerConfig(null, null, "https://1ae2aa9f-4469-4fb7-b457-a6fb0629f397.mock.pstmn.io"),
                null,
                null,
                null,
                null
        );
        Wallet w = new Wallet(walletConfiguration);

        /*String mnemonic = w.genKey(alias, "password");
        KeyPair kp = w.getKeys(alias, "password");

        System.out.println("Public: " + Hex.encode(kp.getPublic().getEncoded()));
        System.out.println("Private: " + Hex.encode(kp.getPrivate().getEncoded()));




        System.out.println(w.recoverPassword(alias, "newPassword", mnemonic));
*/
        KeyPair kp = w.getKeys(alias, "newPassword");
        /*try {
            kp = w.getKeys(alias, "password");
        } catch (IncorrectPasswordException e){
            System.out.println("Contraseña incorrecta");
        }*/

        System.out.println("Private : " +Arrays.toString(kp.getPrivate().getEncoded()));
        System.out.println("Public : " +Arrays.toString(kp.getPublic().getEncoded()));

        String did = w.genDID(kp.getPublic());

        Map<String, Object> claims = Map.of("name", "Eduardo", "familyName", "de la Vega");
        String vc = w.issueVC(claims, did, kp, did, Date.from(Instant.now().plusSeconds(3600)));
        System.out.println("VERIFY: " + w.verifyVCWithoutRegistry(vc));

        //w.genKey("example2", "hola");

        KeyPair kp2 = w.getKeys("example2", "hola");
        String didHolder = w.genDID(kp2.getPublic());

        System.out.println("Private : " +Arrays.toString(kp2.getPrivate().getEncoded()));
        System.out.println("Public : " +Arrays.toString(kp2.getPublic().getEncoded()));


        System.out.println("hola xd\n\n\nhola xd");

        //String vp = w.issueVP(vc, didHolder, kp2, Date.from(Instant.now().plusSeconds(900000)));
        String vp = w.issueVP(vc, did, kp, Date.from(Instant.now().plusSeconds(900000)));


        System.out.println("Verifiable Presentation: " +vp);

        System.out.println(w.verifyVPWithoutRegistry(vp));


        /*KeyHandlerEd25519 keyHandlerEd25519 = new KeyHandlerEd25519(".\\data\\key");


        KeyPair keyPair = keyHandlerEd25519.generateKeys(keyHandlerEd25519.generateSeed(keyHandlerEd25519.generateMnemonic(), ""));



        System.out.println("Private : " +Arrays.toString(keyPair.getPrivate().getEncoded()));
        System.out.println("Public : " +Arrays.toString(keyPair.getPublic().getEncoded()));

        keyHandlerEd25519.storeKey(keyPair, alias, password);

        System.out.println(keyHandlerEd25519.listAlias());

        KeyPair keyPair1 = keyHandlerEd25519.obtainKey(alias);
        System.out.println("Private : " +Arrays.toString(keyPair1.getPrivate().getEncoded()));
        System.out.println("Public : " +Arrays.toString(keyPair1.getPublic().getEncoded()));


        keyHandlerEd25519.destroyKey(alias, "holaxd");


        keyPair.getPrivate().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] signData = new byte[64];
        System.arraycopy(privateKey, 0, signData, 0, 32);
        System.arraycopy(publicKey, 0, signData, 32, 32);

        //Wallet w = new Wallet();
        //w.genKey();*/
    }
}
