package dslab.mailbox;

import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.ConsoleInputMonitor.ConsoleInputMonitorMailboxServer;
import dslab.DMAP;
import dslab.DMTP;
import dslab.nameserver.AlreadyRegisteredException;
import dslab.nameserver.INameserverRemote;
import dslab.nameserver.InvalidDomainException;
import dslab.security.AesCipher;
import dslab.util.Config;
import dslab.util.Keys;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.rmi.NotBoundException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class MailboxServer implements IMailboxServer, Runnable {

    private ServerSocket serverSocketDMTP;
    private ServerSocket serverSocketDMAP;
    private String componentId;
    Config config;
    private final InputStream in;
    private final PrintStream out;
    private final String domain;
    private ExecutorService threadPool;
    private List<Socket> clients = new LinkedList<>(); //All connected Transfer Servers
    private HashMap<String, String> users = new HashMap<>();  // Map for savin usernames and passwords <Username, Password>
    private ConcurrentHashMap<String, ArrayList<DMTP>> emails = new ConcurrentHashMap<>(); // Map for saving the emails for every user <username, List<Emails>>
    private ConcurrentHashMap<String, AtomicInteger> userLastEmailId = new ConcurrentHashMap<>(); // Map to track and create the  IDs of emails for every single user
    private Registry registry;
    private INameserverRemote nameserver;
    private final Log LOG = LogFactory.getLog(MailboxServer.class);

    /**
     * Creates a new server instance.
     *
     * @param componentId the id of the component that corresponds to the Config resource
     * @param config      the component config
     * @param in          the input stream to read console input from
     * @param out         the output stream to write console output to
     */
    public MailboxServer(String componentId, Config config, InputStream in, PrintStream out) {
        this.componentId = componentId;
        this.config = config;
        this.in = in;
        this.out = out;
        threadPool = Executors.newCachedThreadPool();
        domain = config.getString("domain");
    }

    @Override
    public void run() {

        try {
            addUsers();

        } catch (IOException e) {
            throw new UncheckedIOException("Error while adding users to mailbox", e);
        }
        UserLogInWaitThread loginThread = new UserLogInWaitThread(config, this, this.componentId);
        loginThread.start();
        new ConsoleInputMonitorMailboxServer(this).start();
        try {

            serverSocketDMTP = new ServerSocket(config.getInt("dmtp.tcp.port"));
//            LOG.info("Mailbox DMTP serverSocket is up: " + serverSocketDMTP.getLocalSocketAddress());
//            serverSocketDMAP = new ServerSocket(config.getInt("dmap.tcp.port"));
//            LOG.info("Mailbox DMAP serverSocket is up: " + serverSocketDMAP.getLocalSocketAddress());
            registry = LocateRegistry.getRegistry(config.getString("registry.host"), config.getInt("registry.port"));
            nameserver = (INameserverRemote) registry.lookup(config.getString("root_id"));
            nameserver.registerMailboxServer(config.getString("domain"), InetAddress.getLocalHost().getHostAddress() + ":" + serverSocketDMTP.getLocalPort());
            while (!serverSocketDMTP.isClosed()) {
                Socket socket = serverSocketDMTP.accept();
                clients.add(socket);
                threadPool.execute(new ClientHandlerMailDMTP(socket, this));
            }
        } catch (IOException e) {

        } catch (NotBoundException e) {
            throw new RuntimeException(e);
        } catch (AlreadyRegisteredException e) {
            throw new RuntimeException(e);
        } catch (InvalidDomainException e) {
            throw new RuntimeException(e);
        } catch (SecurityException e) {
            LOG.warn(e);
        } finally {
            loginThread.shutDown();
        }
    }

    public void addUsers() throws IOException {

        Config userConfig = new Config(config.getString("users.config"));

        for (String key : userConfig.listKeys()) {
            users.put(key, userConfig.getString(key));
        }

    }

    public InputStream getIn() {
        return in;
    }

    public PrintStream getOut() {
        return out;
    }

    synchronized public void editEmailsAdd(String[] recipients, DMTP email) {


        for (String recipient : recipients) {

            if (emails.containsKey(getUserName(recipient))) {
                emails.get(getUserName(recipient)).add(email);

            } else {

                ArrayList<DMTP> recipientEmails = new ArrayList<>();
                recipientEmails.add(email);
                emails.put(getUserName(recipient), recipientEmails);
            }


            AtomicInteger lastEmailId = userLastEmailId.getOrDefault(recipient, new AtomicInteger());
            long emailId = lastEmailId.incrementAndGet();
            email.setEmailId(emailId);
            userLastEmailId.put(recipient, lastEmailId);
        }


    }

    synchronized public boolean deleteEmailWithId(String user, long emailId) {

        ArrayList<DMTP> updatedEmails = emails.get(user);
        DMTP emailToRemove = null;

        for (DMTP email : updatedEmails) {
            if (email.getEmailId() == emailId) {
                emailToRemove = email;
                break;
            }
        }

        if (emailToRemove != null) {
            updatedEmails.remove(emailToRemove);
            emails.put(user, updatedEmails);
            return true;
        } else {
            return false;
        }

    }

    synchronized public ArrayList<DMTP> getEmails(String user, long emailId) {

        if (emailId < 0) {
            return emails.get(user);
        } else if (emails.get(user) != null) {
            ArrayList<DMTP> toRet = new ArrayList<>();
            for (DMTP email : emails.get(user)) {
                if (email.getEmailId() == emailId) {
                    toRet.add(email);
                    return toRet;
                }
            }
        }
        return null;

    }

    public Map<String, String> getUsers() {
        return users;
    }

    public String getDomain() {
        return domain;
    }

    public String getComponentId() {
        return componentId;
    }

    private String getUserName(String name_domain) {
        return name_domain.split("@")[0];
    }

    @Override
    @Command
    public void shutdown() {
        close();
        threadPool.shutdown();

        for (Socket client : clients) {
            try {
                if (client != null && !client.isClosed()) {
                    client.close();
                }
            } catch (IOException e) {
                throw new UncheckedIOException("Error while closing server ", e);
            }

        }

        clients.clear();
    }

    public void close() {
        if (serverSocketDMTP != null) {
            try {
                serverSocketDMTP.close();
            } catch (IOException e) {
                System.err.println("Error while closing server socket: " + e.getMessage());
            }
        }
    }

    public static void main(String[] args) throws Exception {
        IMailboxServer server = ComponentFactory.createMailboxServer(args[0], System.in, System.out);
        server.run();
    }
}

class ClientHandlerMailDMTP extends Thread {

    final Socket socket;
    final MailboxServer ts;

    public ClientHandlerMailDMTP(Socket s, MailboxServer ts) {
        this.socket = s;
        this.ts = ts;

    }

    @Override
    public void run() {
        PrintWriter output = null;
        BufferedReader input = null;

        while (!socket.isClosed()) {

            try {


                DMTP protocol = new DMTP();
                output =                                            // 2nd statement
                        new PrintWriter(socket.getOutputStream(), true);
                input = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                String inputLine;
                output.println("ok DMTP2.0");


                while ((inputLine = input.readLine()) != null && !protocol.isEnded()) {
                    protocol = protocol.processCommandForMailBox(inputLine, output, protocol, ts.getDomain(), ts.getUsers().keySet());
                    if (protocol.isSent() && !protocol.isEnded()) {
                        ts.editEmailsAdd(protocol.getRecipients().toArray(new String[0]), protocol);
                    }

                }


            } catch (SocketException e) {
                // when the socket is closed, the I/O methods of the Socket will throw a SocketException
                // almost all SocketException cases indicate that the socket was closed
                break;
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (input != null && output != null) {
                    try {
                        input.close();
                        output.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    if (socket != null && !socket.isClosed()) {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                }
            }


        }


    }


}

class ClientHandlerMailDMAP extends Thread {

    final Socket socket;
    final MailboxServer ms;
    private String componentID;
    private AesCipher aesCipher = null;
    private final Log LOG = LogFactory.getLog(ClientHandlerMailDMAP.class);

    public ClientHandlerMailDMAP(Socket s, MailboxServer ms, String componentID) {
        this.socket = s;
        this.ms = ms;
        this.componentID = componentID;
    }

    @Override
    public void run() {
        PrintWriter output = null;
        BufferedReader input = null;

        while (socket != null && !socket.isClosed()) {

            try {


                DMAP protocol = new DMAP(ms, this.componentID);
                output =
                        new PrintWriter(socket.getOutputStream(), true);
                input = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                String inputLine;
                output.println("ok DMAP2.0");
                while ((inputLine = input.readLine()) != null) {
                    if (aesCipher != null) {
                        inputLine = aesCipher.decrypt(inputLine);
                        LOG.info("Client sent request (decrypted): " + inputLine);
                    }

                    String[] parts = inputLine.strip().split("\\s");
                    String command = parts[0];

                    if (command.equals("startsecure")) {
                        try {
                            aesCipher = handshake(output, input);
                            output.println("ok DMAP2.0");
                            output.flush();
                        } catch (Exception e) {
                            throw new SecurityException("Handshake failed", e);
                        }
                    } else {
                    output.println("ok DMAP");
                    output.flush();
                    protocol = protocol.processCommand(inputLine, output, ms.getUsers());
                  }
                }


            } catch (SocketException e) {
                // when the socket is closed, the I/O methods of the Socket will throw a SocketException
                // almost all SocketException cases indicate that the socket was closed
                break;
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (input != null && output != null) {
                    try {
                        input.close();
                        output.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    if (socket != null && !socket.isClosed()) {
                        try {
                            socket.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                }
            }


        }


    }

    public AesCipher handshake(PrintWriter writer, BufferedReader reader) throws
            IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        sendInitialRequest(writer);
        String resolvedChallenge = resolveServerChallenge(reader);
        validateServerResponse(resolvedChallenge);

        aesCipher = initializeAESCipher(resolvedChallenge);
        sendEncryptedResponse(writer, resolvedChallenge);
        confirmHandshake(reader);

        return aesCipher;
    }

    private void sendInitialRequest(PrintWriter writer) {
        writer.println("ok " + ms.getComponentId());
        writer.flush();
    }

    private String resolveServerChallenge(BufferedReader reader) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        return solveChallenge(reader.readLine());
    }

    private void validateServerResponse(String resolvedChallenge) {
        String[] split = resolvedChallenge.split("\\s");
        if (!split[0].equals("ok") || split.length != 4) {
            throw new IllegalArgumentException("Illegal challenge request");
        }
    }

    private AesCipher initializeAESCipher(String resolvedChallenge) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        String[] split = resolvedChallenge.split("\\s");
        return new AesCipher(
                new SecretKeySpec(Base64.getDecoder().decode(split[2]), "AES"),
                Base64.getDecoder().decode(split[3]));
    }

    private void sendEncryptedResponse(PrintWriter writer, String resolvedChallenge) {

        String[] split = resolvedChallenge.split("\\s");
        String response = aesCipher.encrypt("ok " + split[1]);
        LOG.info("Sending solved challenge: " + response);
        writer.println(response);
        writer.flush();
    }

    private void confirmHandshake(BufferedReader reader) throws IOException {
        String request = reader.readLine();
        LOG.info("Handshake accept (encrypted): " + request);
        request = aesCipher.decrypt(request);
        LOG.info("Handshake accept (decrypted): " + request);

        if (!request.equals("ok")) {
            throw new SecurityException("Handshake accept contained wrong response");
        }
    }

    public String solveChallenge(String challenge) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException {

        LOG.info("Solving challenge: " + challenge);

        String decrypted = decryptChallenge(challenge);
        LOG.info("Decrypted challenge: " + decrypted);

        return decrypted;
    }

    private String decryptChallenge(String challenge) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException {

        PrivateKey privateKey = Keys.readPrivateKey(new File("keys/server/" + ms.getComponentId() + ".der"));
        javax.crypto.Cipher decrypterRSA = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decrypterRSA.init(javax.crypto.Cipher.DECRYPT_MODE, privateKey);

        byte[] decodedChallenge = Base64.getDecoder().decode(challenge);
        byte[] decryptedBytes = decrypterRSA.doFinal(decodedChallenge);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}

class UserLogInWaitThread extends Thread {
    private Config config;
    private ServerSocket serverSocketDMAP;
    private List<Socket> clients = new LinkedList<>();
    private ExecutorService threadPool;
    private MailboxServer ms;
    private String componentId;
    private final Log LOG = LogFactory.getLog(UserLogInWaitThread.class);


    public UserLogInWaitThread(Config config, MailboxServer ms, String componentId) {
        this.config = config;
        threadPool = Executors.newCachedThreadPool();
        this.ms = ms;
        this.componentId = componentId;
    }

    @Override
    public void run() {
        try {

            serverSocketDMAP = new ServerSocket(config.getInt("dmap.tcp.port"));
            LOG.info(serverSocketDMAP.getLocalSocketAddress() + "  " + serverSocketDMAP.getLocalPort());
            while (!serverSocketDMAP.isClosed()) {
                LOG.info("1");
                Socket socket = serverSocketDMAP.accept();
                LOG.info("2");
                clients.add(socket);
                LOG.info("3");
                threadPool.execute(new ClientHandlerMailDMAP(socket, ms, this.componentId));
                LOG.info("4");
            }
        } catch (IOException e) {

        } finally {
            if (serverSocketDMAP != null) {
                try {
                    serverSocketDMAP.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public void shutDown() {
        if (serverSocketDMAP != null) {
            try {
                serverSocketDMAP.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        for (Socket client : clients) {
            try {
                if (client != null && !client.isClosed()) {

                    client.close();
                }
            } catch (IOException e) {
                System.err.println("Error while closing  socket: " + e.getMessage());
            }

        }
        threadPool.shutdown();
        clients.clear();

    }
}
