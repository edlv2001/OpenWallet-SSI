package es.edu.walletssi.key.secret;

import es.edu.walletssi.key.KeyHandler;
import io.ipfs.multibase.Base58;
import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.secret.Secret;
import org.didcommx.didcomm.secret.SecretResolver;
import org.jetbrains.annotations.NotNull;

import java.security.KeyPair;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public class SecretResolverDefault implements SecretResolver {
    KeyHandler keyHandler;
    String password;
    public SecretResolverDefault(KeyHandler keyHandler, String password){
        this.keyHandler = keyHandler;
        this.password = password;
    }

    public SecretResolverDefault(KeyHandler keyHandler){
        this.keyHandler = keyHandler;
    }


    public void login(String password) {
        this.password = password;
    }

    public void logout() {
        this.password = null;
        System.gc();
    }


    @NotNull
    @Override
    public Optional<Secret> findKey(@NotNull String s) {
        KeyPair keyPair = this.keyHandler.obtainKey(s, password);
        if(keyPair == null || keyPair.getPrivate() == null)
            return Optional.empty();
        VerificationMaterial verificationMaterial =
                new VerificationMaterial(VerificationMaterialFormat.BASE58, Base58.encode(keyPair.getPrivate().getEncoded()));
        return Optional.of(new Secret(s, keyHandler.getKeyTyp(), verificationMaterial));
    }

    @NotNull
    @Override
    public Set<String> findKeys(@NotNull List<String> list) {
        Set<String> strings = new HashSet<>();
        for (String s : list){
            Optional<Secret> secret = findKey(s);
            if(secret.isPresent())
                strings.add(secret.get().toString());
        }
        return strings;
    }
}
