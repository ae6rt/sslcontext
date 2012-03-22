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

    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void testContext() {
        CustomSSLContextBag customSSLContextBag = new CustomSSLContextBag();
        customSSLContextBag.setStorepass(STOREPASS);
        customSSLContextBag.setKeypass(STOREPASS);
        customSSLContextBag.setKeyStoreFile(new File("keystore.jks"));
        customSSLContextBag.init();

        // Pass this context to the underlying HTTP client in whatever way that client API provides.
        // I can imagine cases where it would want the underlying SSLSocketFactory, too.  YMMV
        SSLContext context = customSSLContextBag.getContext();
        assertNotNull(context);
        SSLSocketFactory socketFactory = context.getSocketFactory();
        assertNotNull(socketFactory);
    }

    @Test
    public void testKeyManager() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream is = new FileInputStream("keystore.jks");
        keyStore.load(is, STOREPASS.toCharArray());
        CustomKeyManager customKeyManager = new CustomKeyManager(keyStore, STOREPASS);
        assertEquals(MYALIAS, customKeyManager.aList.get(0));

        X509Certificate[] x509Certificates = customKeyManager.certMap.get(MYALIAS);
        assertEquals(1, x509Certificates.length);
        X509Certificate x509Certificate = x509Certificates[0];
        Principal subjectDN = x509Certificate.getSubjectDN();
        System.out.println("subjectDN: " + subjectDN);

        PrivateKey privateKey = customKeyManager.privateKeyMap.get(MYALIAS);
        assertNotNull(privateKey);
    }
}

