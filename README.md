
Simple SSLContext bag for Java SSL clients.  Useful when SSL client auth is required, or when the server cert is self-signed
or signed by a CA not represented in the JRE cacerts file.

See org.petrovic.sslcontext.CustomSSLContextTest for typical usage.

The code could be refined to deal with a free-standing KeyStore that contained unusual trust store material.