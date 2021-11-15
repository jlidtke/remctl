package org.eyrie.remctl.client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.net.InetAddress;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Vector;
import java.util.HashMap;
import java.util.Random;
import java.util.Collections;
import java.util.Comparator;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.eyrie.remctl.core.RemctlErrorToken;
import org.eyrie.remctl.core.RemctlException;
import org.eyrie.remctl.core.RemctlFlag;
import org.eyrie.remctl.core.RemctlMessageConverter;
import org.eyrie.remctl.core.RemctlQuitToken;
import org.eyrie.remctl.core.RemctlStatusToken;
import org.eyrie.remctl.core.RemctlToken;
import org.eyrie.remctl.core.RemctlVersionToken;
import org.eyrie.remctl.core.Utils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A connection to a remctl control server that allows you to send and recieve remctl tokens.
 *
 * It is not thread safe.
 *
 * @author pradtke
 *
 */
public class RemctlConnection {

    /** Pattern matching the different bits of data returned by the DNS request for the SRV record. */
    private static final Pattern pattern      = Pattern.compile ("(\\d+) +(\\d+) +(\\d+) +(.+)");

    /** Prefix that SRV records should have. */
    private static       String  srv_prefix   = "_remctl._tcp.";

    /** Some randomness is used to calculate which SRV record should be selected. */
    private static       Random  random       = new Random ();

    /**
     * Allow logging.
     */
    static final Logger logger = LoggerFactory.getLogger(RemctlConnection.class);
    /**
     * Our GSS context.
     */
    private GSSContext gssContext;

    /**
     * Configuration options.
     */
    private Config config;

    /**
     * Converts RemctlTokens to/from their wire representations.
     */
    private RemctlMessageConverter messageConverter;


    /**
     * Data stream sent from the server.
     */
    private DataInputStream inStream;

    /**
     * Data stream sent to the server.
     */
    private DataOutputStream outStream;

    /**
     * Time connection was established.
     */
    private Date connectionEstablishedTime;


    /**
     * RemctlClient that will connect to the provide host, on the default port (4373) using the default principal name
     * 'host/canonical_servername'.
     *
     * @param hostname
     *            the FQDN to connect to.
     */
    public RemctlConnection(final String hostname) {
        this(hostname, 0, null);
    }

    /**
     * Create a remctl connection.
     *
     * @param hostname
     *            The host to connect to
     * @param port
     *            The port to connect on. If 0, defaults to 4373
     * @param serverPrincipal
     *            The server principal. If null, defaults to 'host/canonical_servername'
     */
    public RemctlConnection(final String hostname, final int port, final String serverPrincipal) {
        this(new Config.Builder().withHostname(hostname).withPort(port).withServerPrincipal(serverPrincipal).build());
    }

    /**
     * Create a new remctl connection based on the configuration settings.
     *
     * @param config
     *            The config settings to use.
     */
    public RemctlConnection(final Config config) {
        this.config = config;
    }

    /**
     * Return the port to connect on.
     *
     * @return The port
     */
    public int getPort() {
        return this.config.getPort();
    }

    /**
     * Send the token to the server
     *
     * <p>
     * The token will be encrypted and sent.
     *
     * @param token
     *            The token to send
     */
    public void writeToken(final RemctlToken token) {
        this.messageConverter.encodeMessage(this.outStream, token);

    }

    /**
     * Read a token from the server.
     *
     * @return The next token read from the server
     */
    public RemctlToken readToken() {
        return this.messageConverter.decodeMessage(this.inStream);
    }

    /**
     * Read tokens from the server until a Status or Error Token is reached.
     *
     * @return A list of all tokens (including the ending Status or Error Token) read from the server.
     */
    public List<RemctlToken> readAllTokens() {
        List<RemctlToken> tokenList = new ArrayList<RemctlToken>();

        while (true) {
            RemctlToken outputToken = this.readToken();
            tokenList.add(outputToken);
            logger.debug("read token  {}", outputToken);
            if (outputToken instanceof RemctlErrorToken) {
                break;
            } else if (outputToken instanceof RemctlStatusToken) {
                break;
            } else if (outputToken instanceof RemctlVersionToken) {
                // version token is the end of the tokens
                break;
            }
        }

        return tokenList;
    }

    /**
     * Close this connection if open.
     */
    public void close() {
        if (this.isConnected) {
            this.writeToken(new RemctlQuitToken());
            this.isConnected = false;
        }

    }

    /**
     * Indicates if we are already connected.
     */
    private boolean isConnected = false;

    /**
     * Connect to the remctl server and establish the GSS context.
     *
     * @return true if the client created a new connection, or false if it was already connected
     */
    public boolean connect() {

        if (this.isConnected) {
            return false;
        }

        try {
            this.connectionEstablishedTime = new Date();
            /** Login so can access kerb ticket **/
            LoginContext context = this.config.getLoginContext() == null ? new LoginContext(Utils.LOGIN_MODULE_NAME)
                    : this.config.getLoginContext();
            context.login();
            Subject subject = context.getSubject();
            PrivilegedExceptionAction<Void> pea = new PrivilegedExceptionAction<Void>() {
                @Override
                public Void run() throws Exception {
                    RemctlConnection.this.establishContext();
                    return null;
                }
            };

            Subject.doAs(subject, pea);

            this.messageConverter = new RemctlMessageConverter(this.gssContext);

            this.isConnected = true;
            return this.isConnected;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Connect and establish the context.
     *
     * @throws UnknownHostException
     *             thrown if host doesn't exist
     * @throws IOException
     *             thrown on IO issues
     * @throws GSSException
     *             thrown on GSS issues
     */
    private void establishContext() throws UnknownHostException, IOException, GSSException {
        String host = this.config.getHostname();
        int    port = this.config.getPort();

        if (port == 0) {
            String srv   = srv_resolve(host);
            int    colon = srv.indexOf(":");

            host = srv.substring(0, colon);
            port = Integer.parseInt(srv.substring (colon + 1));
        }

        /**
         * See http://download.oracle.com/javase/1.5.0/docs/guide/security /jgss/tutorials/SampleClient.java for guide.
         */
        Socket socket = new Socket(host, port);
        this.inStream = new DataInputStream(socket.getInputStream());
        this.outStream = new DataOutputStream(socket.getOutputStream());

        logger.debug("Connected to server {} ", socket.getInetAddress());

        String serverPrincipal = this.config.getServerPrincipal();
        if (serverPrincipal == null) {
            String cannonicalName = socket.getInetAddress().getCanonicalHostName().toLowerCase();
            if (!cannonicalName.equalsIgnoreCase(this.config.getHostname())) {
                logger.info("Using Canonical server name in principal ({})", cannonicalName);
            }
            serverPrincipal = "host/" + cannonicalName;
        }

        /*
         * This Oid is used to represent the Kerberos version 5 GSS-API mechanism. It is defined in RFC 1964. We will
         * use this Oid whenever we need to indicate to the GSS-API that it must use Kerberos for some purpose.
         */
        Oid krb5Oid = new Oid("1.2.840.113554.1.2.2");

        GSSManager manager = GSSManager.getInstance();

        /*
         * Create a GSSName out of the server's name. The null indicates that this application does not wish to make any
         * claims about the syntax of this name and that the underlying mechanism should try to parse it as per whatever
         * default syntax it chooses.
         */
        GSSName serverName = manager.createName(serverPrincipal, null);

        /*
         * Create a GSSContext for mutual authentication with the server. - serverName is the GSSName that represents
         * the server. - krb5Oid is the Oid that represents the mechanism to use. The client chooses the mechanism to
         * use. - null is passed in for client credentials - DEFAULT_LIFETIME lets the mechanism decide how long the
         * context can remain valid. Note: Passing in null for the credentials asks GSS-API to use the default
         * credentials. This means that the mechanism will look among the credentials stored in the current Subject to
         * find the right kind of credentials that it needs.
         */
        this.gssContext = manager.createContext(serverName, krb5Oid, null, GSSContext.DEFAULT_LIFETIME);

        // Set the desired optional features on the context. The client
        // chooses these options.

        this.gssContext.requestMutualAuth(true); // Mutual authentication
        this.gssContext.requestConf(true); // Will use confidentiality later
        this.gssContext.requestInteg(true); // Will use integrity later

        // Establish as protocol 2
        byte flag = (byte) (RemctlFlag.TOKEN_NOOP.getValue() ^ RemctlFlag.TOKEN_CONTEXT_NEXT.getValue() ^ RemctlFlag.TOKEN_PROTOCOL
                .getValue());
        this.outStream.writeByte(flag);
        this.outStream.writeInt(0);
        this.outStream.flush();

        // Do the context eastablishment loop

        byte[] token = new byte[0];

        while (!this.gssContext.isEstablished()) {

            // token is ignored on the first call
            token = this.gssContext.initSecContext(token, 0, token.length);
            // Send a token to the server if one was generated by
            // initSecContext
            if (token != null) {
                flag = (byte) (RemctlFlag.TOKEN_CONTEXT.getValue() ^ RemctlFlag.TOKEN_PROTOCOL.getValue());

                this.outStream.writeByte(flag);
                this.outStream.writeInt(token.length);
                this.outStream.write(token);
                this.outStream.flush();
            }

            // If the client is done with context establishment
            // then there will be no more tokens to read in this loop
            if (!this.gssContext.isEstablished()) {
                flag = this.inStream.readByte();
                if ((flag ^ RemctlFlag.TOKEN_PROTOCOL.getValue() ^ RemctlFlag.TOKEN_CONTEXT.getValue()) != 0) {
                    logger.warn("Unexpected token flag {} ", flag);
                }
                token = new byte[this.inStream.readInt()];
                this.inStream.readFully(token);
            }
        }

        logger.debug("Context Established");
        logger.debug("Client is {}", this.gssContext.getSrcName());
        logger.debug("Server is {}", this.gssContext.getTargName());

        /*
         * If mutual authentication did not take place, then only the client was authenticated to the server. Otherwise,
         * both client and server were authenticated to each other.
         */
        if (this.gssContext.getMutualAuthState()) {
            logger.debug("Mutual authentication took place!");
        }
    }

    /**
     * Return the time the connection was established.
     *
     * @return the a copy connectionEstablishedTime
     */
    public Date getConnectionEstablishedTime() {
        return new Date(this.connectionEstablishedTime.getTime());
    }

    /**
     * Checks the input stream for incoming data.
     *
     * <p>
     * Useful for determining if there is unread data buffered on the input stream, prior to sending another command
     * </p>
     *
     * @return true if there is data that can be read.
     */
    public boolean hasPendingData() {
        try {
            return this.inStream.available() > 0;
        } catch (IOException e) {
            throw new RemctlException("Unable to check for pending data", e);
        }
    }

    /**
     * Resolve <em>host</em> with a DNS query and return the first available host:port pair.  If
     * host is not an srv record, or no valid hosts were found from the srv record, return the
     * hostname as passed with DEFAULT_PORT as the port.
     */
    @SuppressWarnings ("unchecked")
    private String srv_resolve (String host)
    {
        String srv_host = host;
        if (! host.startsWith ("_")) {
            srv_host = srv_prefix + host; }

        Vector<SRV_Record>       records = new Vector<SRV_Record> ();
        HashMap<Integer,Integer> totals  = new HashMap<Integer,Integer> ();
        try
        {
            if (! host.contains ("."))
            {
                InetAddress localhost = InetAddress.getLocalHost();
                String      fqdn      = localhost.getCanonicalHostName ();
                String      domain    = fqdn.substring (fqdn.indexOf (".") + 1, fqdn.length ());

                srv_host += "." + domain;
            }

            javax.naming.directory.InitialDirContext iDirC      = new javax.naming.directory.InitialDirContext ();
            javax.naming.directory.Attributes        attributes = iDirC.getAttributes ("dns:/" + srv_host, new String [] { "SRV" });
            javax.naming.directory.Attribute         attr       = attributes.get ("SRV");

            for (int i = 0; i < attr.size (); i ++)
            {
                SRV_Record srv = new SRV_Record ((String)attr.get (i));
                records.add (srv);

                Integer t = totals.get (srv.priority);
                if (t == null) {
                    t = 0; }
                totals.put (srv.priority, t + srv.weight);
            }
            Collections.sort (records);
        }
        catch (Exception ex)
        {
            // ex.printStackTrace ();
            // XXX: log the error?
        }

        String  final_host = host + ":" + Utils.DEFAULT_PORT;
        boolean found_connection = false;
        while (! found_connection && records.size () > 0)
        {
            int current_priority = records.get (0).priority;
            int weight = 0; // running total of the records we've skipped
            int target = 0; // maximum weight of the target we're going to test
            if (totals.get (current_priority) > 0) {
                target = random.nextInt (totals.get (current_priority)); }

            // Go though all of the records adding up the weight until we meet or exceed the target.
            for (int i = 0; i < records.size (); i ++)
            {
                SRV_Record rec = records.get (i);
                weight += rec.weight;
                if (current_priority == rec.priority && weight >= target)
                {
                    if (check_connection (rec.host, rec.port))
                    {
                        found_connection = true;
                        final_host = rec.host + ":" + rec.port;
                    }
                    else
                    {
                        // Remove the attempt and adjust the total weight.
                        records.remove (i);
                        Integer t = totals.get (current_priority);
                        totals.put (current_priority, t - rec.weight);
                    }
                    break;
                }
            }
        }

        return final_host;
    }

    private static boolean check_connection (String host, int port)
    {
        try
        {
            Socket socket = new Socket (host, port);
            socket.close ();
        }
        catch (Exception ex)
        {
            // ex.printStackTrace ();   // XXX: log the error?
            return false;
        }

        return true;
    }



    private class SRV_Record implements Comparable<SRV_Record>, Comparator<SRV_Record>
    {
        public int    priority = 0;
        public int    weight   = 0;
        public int    port     = 0;
        public String host     = "";

        public SRV_Record (String dns_response)
        {
            Matcher m = pattern.matcher (dns_response);

            if (m.matches ())
            {
                priority = Integer.parseInt (m.group (1));
                weight   = Integer.parseInt (m.group (2));
                port     = Integer.parseInt (m.group (3));
                host     = m.group (4).trim ();

                // DNS might include a trailing dot.  Kerberos will choke if it's left.
                if (host.endsWith (".")) {
                    host = host.substring (0, host.length () - 1); }
            }
        }

        public String toString () {
            return priority + " " + weight + " " + port + " " + host; }

        public int compareTo (SRV_Record that) {
            return compare (this, that); }

        public int compare (SRV_Record o1, SRV_Record o2)
        {
                 if (o1 == null && o2 == null) { return  0; }
            else if (o1 == null)               { return -1; }
            else if (o2 == null)               { return  1; }

                 if (o1.priority < o2.priority) { return -1; }
            else if (o1.priority > o2.priority) { return  1; }
            //else
            //{
            //         if (o1.weight < o2.weight) { return -1; }
            //    else if (o1.weight > o2.weight) { return  1; }
            //    else
            //    {
            //             if (o1.port < o2.port) { return -1; }
            //        else if (o1.port > o2.port) { return  1; }
            //    }
            //}

            return 0;
        }
    }
}
