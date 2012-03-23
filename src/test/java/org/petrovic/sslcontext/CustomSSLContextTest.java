package org.petrovic.sslcontext;

import org.apache.commons.httpclient.protocol.Protocol;
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
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import static org.junit.Assert.*;

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
    public void testTrustStore() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore trustStore = keyStoreFromFile(new File("truststore.jks"), STOREPASS);
        Enumeration<String> aliases = trustStore.aliases();
        List<String> aList = new ArrayList<String>();
        while (aliases.hasMoreElements()) {
            aList.add(aliases.nextElement());
        }
        assertEquals(1, aList.size());
        Certificate certificate = trustStore.getCertificate(aList.get(0));
        X509Certificate x509Certificate = (X509Certificate) certificate;
        Principal subjectDN = x509Certificate.getSubjectDN();
        System.out.println("trusted subjectDN: " + subjectDN);
    }

    @Test
    public void testKeyManager() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        assertEquals(MYALIAS, customKeyManager.aList.get(0));

        X509Certificate[] x509Certificates = customKeyManager.certMap.get(MYALIAS);
        assertEquals(1, x509Certificates.length);
        X509Certificate x509Certificate = x509Certificates[0];
        Principal subjectDN = x509Certificate.getSubjectDN();
        System.out.println("client subjectDN: " + subjectDN);

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


    @Test
    public void testCommonsClient() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        CustomSSLContextBag contextBag = new CustomSSLContextBag();
        contextBag.setTrustStore(keyStoreFromFile(new File("truststore.jks"), "changeit")); // contains the new VeriSign cert
        contextBag.setKeyManager(null);  // don't need a keymanager bc server does not require client auth
        contextBag.init();
        Protocol.registerProtocol("https", new Protocol("https", new ApacheSSLSocketFactoryImpl(contextBag.getContext()), 443));

        // doesn't test much, but it should run without exception
        assertTrue(true);
    }

    private KeyStore keyStoreFromFile(File keyStoreFile, String storepass) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream is = new FileInputStream(keyStoreFile);
        keyStore.load(is, storepass.toCharArray());
        return keyStore;
    }
}

