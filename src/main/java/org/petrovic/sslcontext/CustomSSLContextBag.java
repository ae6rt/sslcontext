package org.petrovic.sslcontext;

import org.apache.commons.io.IOUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CustomSSLContextBag {
    private Logger logger = Logger.getLogger(CustomSSLContextBag.class.getName());

    private File keyStoreFileName;
    private String alias;
    private String storepass;
    private String keypass;
    private SSLContext context;

    public CustomSSLContextBag() {
    }

    public void init() {
        try {
            KeyStore clientStore = KeyStore.getInstance("JKS");

            InputStream is = null;
            try {
                is = new FileInputStream(keyStoreFileName);
                clientStore.load(is, storepass.toCharArray());
            } catch (CertificateException ex) {
                logger.log(Level.SEVERE, null, ex);
            } catch (IOException e) {
                logger.severe(String.format("keystore %s cannot be read", keyStoreFileName));
            } finally {
                IOUtils.closeQuietly(is);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            // use cacerts truststore bits by default
            // but you should be able to use a non-null value to teach the context about remote certs not in cacerts
            tmf.init((KeyStore) null);

            java.security.cert.Certificate[] _certChain = clientStore.getCertificateChain(alias);
            X509Certificate[] certChain = new X509Certificate[_certChain.length];
            for (int i = 0; i < _certChain.length; ++i) {
                certChain[i] = (X509Certificate) _certChain[i];
            }

            PrivateKey key = (PrivateKey) clientStore.getKey(alias, keypass.toCharArray());
            CustomKeyManager vectorKeyManager = new CustomKeyManager(alias, key, certChain);
            KeyManager[] keyManagers = {vectorKeyManager};

            context = SSLContext.getInstance("TLS");
            context.init(keyManagers, tmf.getTrustManagers(), null);

            if (logger.isLoggable(Level.FINE)) {
                logger.fine(String.format("Client cert for %s: %s", keyStoreFileName, clientStore.getCertificate(alias)));
            }
        } catch (UnrecoverableKeyException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
    }

    public File getKeyStoreFileName() {
        return keyStoreFileName;
    }

    public void setKeyStoreFileName(File keyStoreFileName) {
        this.keyStoreFileName = keyStoreFileName;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getStorepass() {
        return storepass;
    }

    public void setStorepass(String storepass) {
        this.storepass = storepass;
    }

    public String getKeypass() {
        return keypass;
    }

    public void setKeypass(String keypass) {
        this.keypass = keypass;
    }
}