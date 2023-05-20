package org.example.walletssi.model.resolver;

import foundation.identity.did.DIDDocument;

public interface DIDResolver {
    public DIDDocument resolveDID(String did);
}
