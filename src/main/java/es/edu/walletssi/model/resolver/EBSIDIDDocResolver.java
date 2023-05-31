package es.edu.walletssi.model.resolver;

import es.edu.walletssi.model.DidMethod;
import es.edu.walletssi.model.didUtils.DIDDocImp;
import es.edu.walletssi.model.didUtils.DIDParser;
import es.edu.walletssi.model.handlers.config.EBSIMethodHandlerConfig;
import foundation.identity.did.DIDDocument;
import org.didcommx.didcomm.diddoc.DIDDoc;
import org.didcommx.didcomm.diddoc.DIDDocResolver;
import org.jetbrains.annotations.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;


import java.net.URI;
import java.util.Optional;

public class EBSIDIDDocResolver implements DIDDocResolver {

    private URI didRegistry;

    public EBSIDIDDocResolver(EBSIMethodHandlerConfig config) {
        this.didRegistry = URI.create(config.getDidRegistry());
    }

    @NotNull
    @Override
    public Optional<DIDDoc> resolve(@NotNull String did) {
        if (!DIDParser.isValid(did, DidMethod.EBSI)) {
            return Optional.empty();
        }
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(didRegistry + "/did?did=" + did, String.class);
        if (response == null || response.getBody() == null || response.getBody().isEmpty()) {
            return Optional.empty();
        }
        try {
            DIDDocImp didDocImp = DIDDocImp.Companion.fromJson(response.getBody());
            DIDDoc decodedDoc = new DIDDoc(did, didDocImp.getKeyAgreements(), didDocImp.getAuthentications(), didDocImp.getVerificationMethods(), didDocImp.getDidCommServices());
            return Optional.of(decodedDoc);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return Optional.empty();
    }

    public DIDDocument resolveDID(String did) {
        if (!DIDParser.isValid(did, DidMethod.EBSI)) {
            return null;
        }
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> response = restTemplate.getForEntity(didRegistry + "/did?did=" + did, String.class);
        if (response == null || response.getBody() == null || response.getBody().isEmpty()) {
            return null;
        }

        DIDDocument didDocument = DIDDocument.fromJson(response.getBody());

        return didDocument;
    }
}
