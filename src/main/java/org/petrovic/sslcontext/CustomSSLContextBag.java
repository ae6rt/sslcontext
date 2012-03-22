package org.petrovic.sslcontext;

import org.apache.commons.io.IOUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CustomSSLContextBag {
    private Logger logger = Logger.getLogger(CustomSSLContextBag.class.getName());

    private File keyStoreFile;
    private File trustStoreFile = null;
    //    private String alias;
    private String storepass;
    private String keypass;
    private SSLContext context;
    private X509KeyManager keyManager;

    public CustomSSLContextBag() {
    }

    public void init() {
        try {
            // The key store and trust store are JKS keystores assumed to have the same storepass.  If you control both files, this
            // is not a burdensome requirement.
            KeyStore clientStore = KeyStore.getInstance("JKS");
            KeyStore trustStore = null;

            InputStream is = null;
            try {
                is = new FileInputStream(keyStoreFile);
                clientStore.load(is, storepass.toCharArray());

                // init an optional keystore containing trust material (certs)
                if (trustStoreFile != null) {
                    trustStore = KeyStore.getInstance("JKS");
                    is = new FileInputStream(trustStoreFile);
                    trustStore.load(is, storepass.toCharArray());
                }
            } catch (CertificateException ex) {
                logger.log(Level.SEVERE, null, ex);
            } catch (IOException e) {
                logger.severe(String.format("keystore %s cannot be read", keyStoreFile));
            } finally {
                IOUtils.closeQuietly(is);
            }

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            // use cacerts truststore bits by default
            // but you should be able to use a non-null value to inform the context about server certs not in cacerts
            tmf.init(trustStore);

            keyManager = new CustomKeyManager(clientStore, storepass);
            KeyManager[] keyManagers = {keyManager};

            context = SSLContext.getInstance("TLS");
            getContext().init(keyManagers, tmf.getTrustManagers(), null);
        } catch (KeyManagementException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
    }

    public File getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(File keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
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

    public SSLContext getContext() {
        return context;
    }

    public X509KeyManager getKeyManager() {
        return keyManager;
    }

    public void setKeyManager(X509KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public File getTrustStoreFile() {
        return trustStoreFile;
    }

    public void setTrustStoreFile(File trustStoreFile) {
        this.trustStoreFile = trustStoreFile;
    }
}