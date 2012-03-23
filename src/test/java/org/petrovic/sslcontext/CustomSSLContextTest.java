package org.petrovic.sslcontext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author petrovic -- 3/22/12 11:19 AM
 */
public class CustomSSLContextTest {

    public static final String STOREPASS = "changeit";
    public static final String MYALIAS = "myalias";
    public static final String KEYSTORE = "keystore.jks";

    private CustomKeyManager customKeyManager;

    @Before
    public void setUp() throws Exception {
        KeyStore keyStore = keyStoreFromFile(new File(KEYSTORE), STOREPASS);
        customKeyManager = new CustomKeyManager();
        customKeyManager.setKeyStore(keyStore);
        customKeyManager.setKeypass(STOREPASS);
        customKeyManager.init();
    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void testKeyManager() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        assertEquals(MYALIAS, customKeyManager.aList.get(0));

        X509Certificate[] x509Certificates = customKeyManager.certMap.get(MYALIAS);
        assertEquals(1, x509Certificates.length);
        X509Certificate x509Certificate = x509Certificates[0];
        Principal subjectDN = x509Certificate.getSubjectDN();
        System.out.println("subjectDN: " + subjectDN);

        PrivateKey privateKey = customKeyManager.privateKeyMap.get(MYALIAS);
        assertNotNull(privateKey);
    }

    @Test
    public void testContext() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        CustomSSLContextBag customSSLContextBag = new CustomSSLContextBag();
        customSSLContextBag.setKeyManager(customKeyManager);
        customSSLContextBag.setTrustStore(null);
        customSSLContextBag.init();

        // Pass this context to the underlying HTTP client in whatever way that client API provides.
        SSLContext context = customSSLContextBag.getContext();
        assertNotNull(context);

        // I can imagine cases where it would want the underlying SSLSocketFactory, too.  YMMV
        SSLSocketFactory socketFactory = context.getSocketFactory();
        assertNotNull(socketFactory);
    }

    private KeyStore keyStoreFromFile(File keyStoreFile, String storepass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream is = new FileInputStream(keyStoreFile);
        keyStore.load(is, storepass.toCharArray());
        return keyStore;
    }
}

