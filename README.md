
Simple SSLContext bag for Java SSL clients.  Useful when SSL client auth is required, or when the server cert is self-signed or signed by a CA not represented in the JRE cacerts file.

See org.petrovic.sslcontext.SSLContextTest for typical usage.

While there is no Spring herein, the context bag and key manager are crafted as to be used as simple Spring beans with
zero-arg ctors and a post-contstruct init() method.

Reference:  http://www.amazon.com/Beginning-Cryptography-Java-David-Hook/dp/0764596330
