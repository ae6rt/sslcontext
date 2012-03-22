package org.petrovic.sslcontext;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.File;

import static org.junit.Assert.assertNotNull;

/**
 * @author petrovic -- 3/22/12 11:19 AM
 */
public class CustomSSLContextTest {
    @Before
    public void setUp() throws Exception {

    }

    @After
    public void tearDown() throws Exception {

    }

    @Test
    public void testContext() {
        CustomSSLContextBag customSSLContextBag = new CustomSSLContextBag();
        customSSLContextBag.setAlias("myalias");
        customSSLContextBag.setStorepass("changeit");
        customSSLContextBag.setKeypass("changeit");
        customSSLContextBag.setKeyStoreFile(new File("keystore.jks"));
        customSSLContextBag.init();

        // Pass this context to the underlying HTTP client in whatever way that client API provides.
        // I can imagine cases where it would want the underlying SSLSocketFactory, too.  YMMV
        SSLContext context = customSSLContextBag.getContext();
        assertNotNull(context);
        SSLSocketFactory socketFactory = context.getSocketFactory();
        assertNotNull(socketFactory);
    }
}
