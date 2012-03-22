package org.petrovic.sslcontext;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Super simple key manager.  This class drives which key you present for use for SSL client auth.
 */
public class CustomKeyManager implements X509KeyManager {

    public final List<String> aList = new ArrayList<String>();
    public final Map<String, PrivateKey> privateKeyMap = new HashMap<String, PrivateKey>();
    public final Map<String, X509Certificate[]> certMap = new HashMap<String, X509Certificate[]>();

    public CustomKeyManager(KeyStore keystore, String keypass) {
        try {
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                aList.add(aliases.nextElement());
            }
            for (String s : aList) {
                java.security.cert.Certificate[] _certChain = keystore.getCertificateChain(s);
                X509Certificate[] certChain = new X509Certificate[_certChain.length];
                for (int i = 0; i < _certChain.length; ++i) {
                    certChain[i] = (X509Certificate) _certChain[i];
                }
                certMap.put(s, certChain);
                PrivateKey key = (PrivateKey) keystore.getKey(s, keypass.toCharArray());
                privateKeyMap.put(s, key);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
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
        // just return the first alias itself.
        return aList.get(0);
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
        return certMap.get(alias);
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
        return privateKeyMap.get(alias);
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
