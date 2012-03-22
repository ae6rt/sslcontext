package org.petrovic.sslcontext;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Super simple key manager.
 */
public class CustomKeyManager implements X509KeyManager {
    private final String alias;
    private final PrivateKey key;
    private final X509Certificate[] certs;

    public CustomKeyManager(String alias, PrivateKey key, X509Certificate[] certChain) {
        this.alias = alias;
        this.key = key;
        this.certs = certChain;
    }

    /**
     * Choose an alias to authenticate the client side of a secure socket given the public key type and the list of certificate issuer authorities recognized by the peer (if any).
     *
     * @param keyTypes
     * @param issuers
     * @param socket
     * @return
     */
    @Override
    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        // Choosing the alias could be more elaborate, and would be based on the method arguments.  For now,
        // just return alias itself.
        return alias;
    }

    /**
     * Returns the certificate chain associated with the given alias.
     *
     * @param alias
     * @return
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        // You could choose the cert chain based on the alias, but for now just return the one chain we know about.
        return certs;
    }

    /**
     * Returns the key associated with the given alias.
     *
     * @param alias
     * @return
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        // You could choose the key based on the alias, but for now just return the one key we know about.
        return key;
    }

    /**
     * Choose an alias to authenticate the server side of a secure socket given the public key type and the list of certificate issuer authorities recognized by the peer (if any).
     *
     * @param keyType
     * @param issuers
     * @param socket
     * @return
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        // If you get this exception, then do something smarter here.
        throw new UnsupportedOperationException("chooseServerAlias not implemented");
    }

    /**
     * Get the matching aliases for authenticating the client side of a secure socket given the public key type and the list of certificate issuer authorities recognized by the peer (if any).
     *
     * @param keyType
     * @param issuers
     * @return
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        // If you get this exception, then do something smarter here.
        throw new UnsupportedOperationException("getClientAliases not implemented");
    }

    /**
     * Get the matching aliases for authenticating the server side of a secure socket given the public key type and the list of certificate issuer authorities recognized by the peer (if any).
     *
     * @param keyType
     * @param issuers
     * @return
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        // If you get this exception, then do something smarter here.
        throw new UnsupportedOperationException("getServerAliases not implemented");
    }
}
