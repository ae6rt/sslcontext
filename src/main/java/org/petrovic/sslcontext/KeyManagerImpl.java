package org.petrovic.sslcontext;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Super simple key manager.  This class drives which key you present for use during SSL client auth.
 */
public class KeyManagerImpl implements X509KeyManager {

    private Logger logger = Logger.getLogger(KeyManagerImpl.class.getName());

    public List<String> aliases;
    public Map<String, PrivateKey> privateKeyMap;
    public Map<String, X509Certificate[]> certificateMap;

    private KeyStore keyStore;
    private String keypass;

    public KeyManagerImpl() {
    }

    public void init() {
        List<String> tList = new ArrayList<String>();
        Map<String, PrivateKey> pMap = new HashMap<String, PrivateKey>();
        Map<String, X509Certificate[]> cMap = new HashMap<String, X509Certificate[]>();
        try {
            Enumeration<String> enumeration = keyStore.aliases();
            while (enumeration.hasMoreElements()) {
                tList.add(enumeration.nextElement());
            }
            for (String s : tList) {
                java.security.cert.Certificate[] _certChain = keyStore.getCertificateChain(s);
                X509Certificate[] certChain = new X509Certificate[_certChain.length];
                for (int i = 0; i < _certChain.length; ++i) {
                    certChain[i] = (X509Certificate) _certChain[i];
                }
                cMap.put(s, certChain);
                PrivateKey key = (PrivateKey) keyStore.getKey(s, keypass.toCharArray());
                pMap.put(s, key);
            }
            aliases = Collections.unmodifiableList(tList);
            privateKeyMap = Collections.unmodifiableMap(pMap);
            certificateMap = Collections.unmodifiableMap(cMap);
        } catch (KeyStoreException e) {
            logger.log(Level.SEVERE, null, e);
        } catch (UnrecoverableKeyException e) {
            logger.log(Level.SEVERE, null, e);
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, null, e);
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
        return aliases.get(0);
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
        return certificateMap.get(alias);
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

    public void setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    public void setKeypass(String keypass) {
        this.keypass = keypass;
    }
}
