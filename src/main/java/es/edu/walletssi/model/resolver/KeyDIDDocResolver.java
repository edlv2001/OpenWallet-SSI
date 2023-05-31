package es.edu.walletssi.model.resolver;

import es.edu.walletssi.key.utils.KeyUtils;
import es.edu.walletssi.model.didUtils.DIDParser;
import es.edu.walletssi.model.exception.UnsupportedKeyAlgorithm;
import io.ipfs.multibase.Multibase;
import org.didcommx.didcomm.common.VerificationMaterial;
import org.didcommx.didcomm.common.VerificationMaterialFormat;
import org.didcommx.didcomm.common.VerificationMethodType;
import org.didcommx.didcomm.diddoc.DIDDoc;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.didcommx.didcomm.diddoc.VerificationMethod;
import es.edu.walletssi.key.KeyHandlerEd25519;
import es.edu.walletssi.model.DidMethod;
import org.jetbrains.annotations.NotNull;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class KeyDIDDocResolver implements DIDDocResolver {
    @NotNull
    @Override
    public Optional<DIDDoc> resolve(@NotNull String did) {
        if (!DIDParser.isValid(did, DidMethod.KEY)) {
            return Optional.empty();
        }

        String identifier = did.substring(8);
        String auth = did + "#" + identifier;
        List<String> authentications = List.of(auth);
        List<String> assertionMethod = List.of(auth);
        VerificationMaterial material = new VerificationMaterial(VerificationMaterialFormat.JWK, KeyUtils.publicKeyToJWK(getKey(identifier)).toJSONString());
        VerificationMethod verificationMethod = new VerificationMethod(auth, VerificationMethodType.JSON_WEB_KEY_2020, material, did);
        DIDDoc didDoc = new DIDDoc(did, new ArrayList<>(), authentications, List.of(verificationMethod), new ArrayList<>());

        return Optional.of(didDoc);
    }

    private PublicKey getKey(String didIdentifier){
        if(didIdentifier.startsWith("z6Mk"))
            return new KeyHandlerEd25519.PublicKeyEd25519(decodeKey(didIdentifier));
        if(didIdentifier.startsWith("z4MX") || didIdentifier.startsWith("zBbU")){
            byte[] keyDecoded = decodeKey(didIdentifier);
            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                return keyFactory.generatePublic(new X509EncodedKeySpec(keyDecoded));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        throw new UnsupportedKeyAlgorithm("Unsupported Key Type or Invalid DID Key");
    }

    private byte[] decodeKey(String id){
        byte[] b = Multibase.decode(id);
        return Arrays.copyOfRange(b, 2, b.length);
    }
}
