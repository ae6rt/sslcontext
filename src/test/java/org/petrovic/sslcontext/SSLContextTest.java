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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
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
public class SSLContextTest {

    /*
   The content of these keystores are not actually related.  Their respective contents are valid, but not correlated
   in any real way.
    */
    private final String KEYSTORE = "keystore.jks";
    private final String TRUSTSTORE = "truststore.jks";

    private final String STOREPASS = "changeit";
    private final String HTTPS = "https";
    private final String MYALIAS = "myalias";
    private KeyManagerImpl keyManagerImpl;
    private KeyStore trustStore;

    @Before
    public void setUp() throws Exception {
        KeyStore keyStore = keyStoreFromFile(new File(KEYSTORE), STOREPASS);
        keyManagerImpl = new KeyManagerImpl();
        keyManagerImpl.setKeyStore(keyStore);
        keyManagerImpl.setKeypass(STOREPASS);
        keyManagerImpl.init();

        trustStore = keyStoreFromFile(new File(TRUSTSTORE), STOREPASS);
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testTrustStore() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore trustStore = keyStoreFromFile(new File(TRUSTSTORE), STOREPASS);
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
        assertEquals(MYALIAS, keyManagerImpl.aliases.get(0));

        X509Certificate[] x509Certificates = keyManagerImpl.certificateMap.get(MYALIAS);
        assertEquals(1, x509Certificates.length);
        X509Certificate x509Certificate = x509Certificates[0];
        Principal subjectDN = x509Certificate.getSubjectDN();
        System.out.println("client subjectDN:  " + subjectDN);

        PrivateKey privateKey = keyManagerImpl.privateKeyMap.get(MYALIAS);
        assertNotNull(privateKey);
    }

    @Test
    public void testContextA() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        SSLContextBag SSLContextBag = new SSLContextBag();
        SSLContextBag.setKeyManager(keyManagerImpl);
        SSLContextBag.setTrustStore(trustStore);
        SSLContextBag.init();

        // Pass this context to the underlying HTTP client in whatever way that client API provides.
        SSLContext context = SSLContextBag.getContext();
        assertNotNull(context);

        // I can imagine cases where it would want the underlying SSLSocketFactory, too.  YMMV
        SSLSocketFactory socketFactory = context.getSocketFactory();
        assertNotNull(socketFactory);
    }

    /*
    This test should generate what is essentially the default SSLContext characterized by no special key manager or trust store.
     */
    @Test
    public void testContextB() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        SSLContextBag SSLContextBag = new SSLContextBag();
        SSLContextBag.setKeyManager(null);
        SSLContextBag.setTrustStore(null);
        SSLContextBag.init();

        // Pass this context to the underlying HTTP client in whatever way that client API provides.
        SSLContext context = SSLContextBag.getContext();
        assertNotNull(context);

        // I can imagine cases where it would want the underlying SSLSocketFactory, too.  YMMV
        SSLSocketFactory socketFactory = context.getSocketFactory();
        assertNotNull(socketFactory);
    }


    /*
    Verify that we can create an Apache HTTP Client custom protocol from out SSLContext.
     */
    @Test
    public void testCommonsClient() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        SSLContextBag contextBag = new SSLContextBag();
        contextBag.setTrustStore(keyStoreFromFile(new File(TRUSTSTORE), STOREPASS));
        contextBag.setKeyManager(keyManagerImpl);
        contextBag.init();
        Protocol.registerProtocol(HTTPS, new Protocol(HTTPS, new ApacheSSLSocketFactoryImpl(contextBag.getContext()), 443));

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

