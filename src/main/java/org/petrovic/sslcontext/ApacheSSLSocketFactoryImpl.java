package org.petrovic.sslcontext;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.*;

/**
 * http://svn.apache.org/viewvc/httpcomponents/oac.hc3x/trunk/src/contrib/org/apache/commons/httpclient/contrib/ssl/EasySSLProtocolSocketFactory.java?revision=661391&view=co
 */
public class ApacheSSLSocketFactoryImpl implements SecureProtocolSocketFactory {

    private SSLContext context;

    public ApacheSSLSocketFactoryImpl(SSLContext context) {
        this.context = context;
    }

    public Socket createSocket(Socket socket, String s, int i, boolean b) throws IOException, UnknownHostException {
        return context.getSocketFactory().createSocket(socket, s, i, b);
    }

    public Socket createSocket(String s, int i, InetAddress inetAddress, int i1) throws IOException, UnknownHostException {
        return context.getSocketFactory().createSocket(s, i, inetAddress, i1);
    }

    public Socket createSocket(String host, int port, InetAddress inetAddress, int i1, HttpConnectionParams params)
            throws IOException, UnknownHostException, ConnectTimeoutException {
        if (params == null) {
            throw new IllegalArgumentException("Parameters may not be null");
        }
        int timeout = params.getConnectionTimeout();
        SocketFactory socketfactory = context.getSocketFactory();
        if (timeout == 0) {
            return socketfactory.createSocket(host, port, inetAddress, i1);
        } else {
            Socket socket = socketfactory.createSocket();
            SocketAddress localaddr = new InetSocketAddress(inetAddress, i1);
            SocketAddress remoteaddr = new InetSocketAddress(host, port);
            socket.bind(localaddr);
            socket.connect(remoteaddr, timeout);
            return socket;
        }
    }

    public Socket createSocket(String s, int i) throws IOException, UnknownHostException {
        return context.getSocketFactory().createSocket(s, i);
    }
}
