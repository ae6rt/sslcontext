package org.petrovic.sslcontext;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class CustomSSLContextBag {
    private SSLContext context;
    private X509KeyManager keyManager;
    private KeyStore trustStore = null;

    public CustomSSLContextBag() {
    }

    public void init() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            // use cacerts truststore bits by default
            // but you should be able to use a non-null value to inform the context about server certs not in cacerts
            tmf.init(trustStore);
            KeyManager[] keyManagers = {keyManager};
            context = SSLContext.getInstance("TLS");
            context.init(keyManagers, tmf.getTrustManagers(), null);
        } catch (KeyManagementException ex) {
            throw new RuntimeException(ex);
        } catch (KeyStoreException ex) {
            throw new RuntimeException(ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    public SSLContext getContext() {
        return context;
    }

    public void setKeyManager(X509KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public void setTrustStore(KeyStore trustStore) {
        this.trustStore = trustStore;
    }
}