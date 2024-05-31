package dslab.transfer;

import dslab.ComponentFactory;
import dslab.ConsoleInputMonitor.ConsoleInputMonitorTransferServer;
import dslab.DMTP;
import dslab.mailbox.MailboxServer;
import dslab.nameserver.INameserverRemote;
import dslab.util.Config;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.*;
import java.net.*;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;


public class TransferServer implements ITransferServer, Runnable {
    private ServerSocket serverSocket;
    private String componentId;
    private Config config;
    private InputStream in;
    private PrintStream out;
    private ExecutorService threadPool;
    private boolean shuttingDown = false;
    private BlockingQueue<DMTP> emails = new LinkedBlockingQueue<>();   // Queue for saving the emails to be sent.
    private List<Socket> clients; // All Client Connections

    private LinkedHashMap<String, String> mailboxServers = new LinkedHashMap<>(); //Available Mailbox Servers
    private Registry registry;
    private INameserverRemote nameserver;

    private final Log LOG = LogFactory.getLog(TransferServer.class);


    /**
     * Creates a new server instance.
     *
     * @param componentId the id of the component that corresponds to the Config resource
     * @param config      the component config
     * @param in          the input stream to read console input from
     * @param out         the output stream to write console output to
     */
    public TransferServer(String componentId, Config config, InputStream in, PrintStream out) {
        this.componentId = componentId;
        this.config = config;
        this.in = in;
        this.out = out;
        threadPool = Executors.newCachedThreadPool();
        clients = new LinkedList<>();
    }

    @Override
    public void run() {

        new ConsoleInputMonitorTransferServer(this).start();
        MessageToMailBox forwarding = new MessageToMailBox(null, mailboxServers, "aaa", this);
        forwarding.start();
        try {

            BufferedReader reader = new BufferedReader(new FileReader("src/main/resources/domains.properties"));
            String line;
            reader.readLine();
            reader.readLine();
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("=");
                mailboxServers.put(parts[0], parts[1]);
            }

            serverSocket = new ServerSocket(config.getInt("tcp.port"));
            registry = LocateRegistry.getRegistry(config.getString("registry.host"), config.getInt("registry.port"));
            nameserver = (INameserverRemote) registry.lookup(config.getString("root_id"));

            while (!serverSocket.isClosed()) {

                Socket socket = serverSocket.accept();
                clients.add(socket);

                threadPool.execute(new ClientHandler(socket, this));
            }
        } catch (IOException | NotBoundException e) {

        } finally {
            forwarding.stopForwarding();
        }


    }

    public void addEmail(DMTP email) throws InterruptedException {
        this.emails.put(email);
    }

    public DMTP getEmail() throws InterruptedException {

        DMTP toRet = this.emails.take();
        return toRet;
    }

    public void close() {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                throw new UncheckedIOException("Error while closing server socket", e);

            }
        }
    }

    public Config getConfig() {
        return config;
    }

    public boolean getShuttingDown() {
        return shuttingDown;
    }

    public InputStream getIn() {
        return in;
    }

    public PrintStream getOut() {
        return out;
    }

    public Registry getRegistry() {
        return registry;
    }

    public INameserverRemote getNameserver() {
        return nameserver;
    }

    @Override
    public void shutdown() throws IOException {


        shuttingDown = true;
        close();
        threadPool.shutdown();

        for (Socket client : clients) {
            try {
                if (client != null && !client.isClosed()) {
                    client.close();
                }
            } catch (IOException e) {
                System.err.println("Error while closing  socket: " + e.getMessage());
            }

        }

        clients.clear();
    }

    public static void main(String[] args) throws Exception {
        ITransferServer server = ComponentFactory.createTransferServer(args[0], System.in, System.out);
        server.run();
    }

}

class ClientHandler extends Thread {

    final Socket socket;
    final TransferServer ts;

    public ClientHandler(Socket s, TransferServer ts) {
        this.socket = s;
        this.ts = ts;

    }


    @Override
    public void run() {
        PrintWriter output = null;
        BufferedReader input = null;

        while (!ts.getShuttingDown() && !socket.isClosed()) {

            try {


                DMTP protocol = new DMTP();
                output =                                            // 2nd statement
                        new PrintWriter(socket.getOutputStream(), true);
                input = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                String inputLine;
                output.println("ok DMTP2.0");
                while (!ts.getShuttingDown() && (inputLine = socket.isClosed() ? null : input.readLine()) != null) {

                    if (protocol.isEnded()) {
                        output.println("Email sent");
                        break;
                    } else {

                        protocol = protocol.processCommand(inputLine, output, protocol);


                        if (protocol.isSent() && !protocol.isEnded()) {
                            ts.addEmail(protocol);
                        }
                    }
                }


            } catch (SocketException e) {
                // when the socket is closed, the I/O methods of the Socket will throw a SocketException
                // almost all SocketException cases indicate that the socket was closed
                break;
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            } finally {
                if (input != null) {
                    try {
                        input.close();
                        output.close();

                        if (!socket.isClosed()) {
                            try {
                                socket.close();
                            } catch (IOException e) {
                                throw new RuntimeException(e);
                            }
                        }

                    } catch (IOException e) {
                        throw new UncheckedIOException("Error while closing socket", e);

                    }
                }


            }


        }
    }


}

class MessageToMailBox extends Thread {

    private DMTP[] emailsToSend;
    private HashMap<String, String> supportedDomains;

    private String transferServerID;

    private TransferServer ts;

    public MessageToMailBox(DMTP[] emailsToSend, LinkedHashMap<String, String> supportedDomains, String transferServerID, TransferServer ts) {
        this.ts = ts;
        this.emailsToSend = emailsToSend;
        this.supportedDomains = supportedDomains;
        this.transferServerID = transferServerID;
    }

    @Override
    public void run() {
        while (!ts.getShuttingDown()) {
            try {

                forwardMessage(ts.getEmail());

            } catch (InterruptedException e) {
                break;
            } catch (RemoteException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void forwardMessage(DMTP email) throws RemoteException {
        LinkedList<String> errors = new LinkedList<>();

        int countMB = 0;
        for (Map.Entry<String, String> entry : supportedDomains.entrySet()) {
            String domain = entry.getKey();
            String[] values = entry.getValue().split(":");
            String[] addr = makeLookUp(domain);
            String ip = addr[0].trim();
            int port = Integer.parseInt(addr[1].trim());
            for (String sentTo : email.getRecipients()) {
                String[] recipients = sentTo.split("@");
                String recipientDomain = recipients[1].trim();
                if (recipientDomain.equals(domain)) {
                    countMB++;
                    Socket socket = null;

                    try {
                        socket = new Socket(ip, port);
                        BufferedReader serverReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                        PrintWriter serverWriter = new PrintWriter(socket.getOutputStream(), true);

                        serverWriter.println("begin ");
                        serverWriter.flush();
                        if (!serverReader.readLine().startsWith("ok")) {
                            errors.add("error DMTP");
                        }

                        serverWriter.println("to " + email.getRecipients());


                        if (!serverReader.readLine().startsWith("ok")) {
                            errors.add("error DMTP");
                        }

                        serverWriter.println("from " + email.getSender());
                        if (!serverReader.readLine().startsWith("ok")) {
                            errors.add("error DMTP");
                        }
                        serverWriter.println("subject " + email.getSubject());
                        if (!serverReader.readLine().startsWith("ok")) {
                            errors.add("error DMTP");
                        }
                        serverWriter.println("data " + email.getData());
                        if (!serverReader.readLine().startsWith("ok")) {
                            errors.add("error DMTP");
                        }
                        serverWriter.println("send");
                        if (!serverReader.readLine().startsWith("ok")) {
                            errors.add("error DMTP");
                        }
                        serverWriter.println("quit");
                        if (!serverReader.readLine().startsWith("ok")) {
                            errors.add("error DMTP");
                        }
                        if (!errors.isEmpty()) {
                            notifyClientForError(email.getSender(), errors);
                        }


                        try (DatagramSocket datagramSocket = new DatagramSocket()) {
                            byte[] buffer = new byte[1024];
                            DatagramPacket packet;
                            InetAddress address = InetAddress.getLocalHost();
                            String serverIP = address.getHostAddress();
                            String portDG = ts.getConfig().getString("tcp.port");
                            String data = serverIP + ":" + portDG + " " + email.getSender();
                            buffer = data.getBytes();
                            String monitoringAddress = ts.getConfig().getString("monitoring.host");
                            int monitoringPort = ts.getConfig().getInt("monitoring.port");

                            packet = new DatagramPacket(buffer, buffer.length, InetAddress.getByName(monitoringAddress), monitoringPort);

                            datagramSocket.send(packet);
                        } catch (IOException e) {
                            // Handle exceptions related to DatagramSocket, if needed
                            e.printStackTrace();
                        }

                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    } finally {
                        try {
                            if (socket != null) {
                                socket.close();
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }

                    }

                }
            }
            if (countMB == 0) {
                errors.add("No such a mailbox");
                notifyClientForError(email.getSender(), errors);
            }
        }
    }

    private String[] makeLookUp(String server) throws RemoteException {

        String[] split = server.split("\\.");
        INameserverRemote nextServer = ts.getNameserver();
        for (int i = split.length - 1; i > 0; i--) {
            nextServer = nextServer.getNameserver(split[i]);
        }
        String[] addr = nextServer.lookup(split[0]).split(":");
        return addr;
    }

    private void notifyClientForError(String sender, LinkedList<String> errors) {
        for (Map.Entry<String, String> entry : supportedDomains.entrySet()) {
            String domain = entry.getKey();
            String[] values = entry.getValue().split(":");
            String ip = values[0].trim();
            int port = Integer.parseInt(values[1].trim());
            String[] recipients = sender.split("@");
            String recipientDomain = recipients[1].trim();
            Socket socket = null;
            if (recipientDomain.equals(domain)) {

                try {
                    socket = new Socket(ip, port);
                    BufferedReader serverReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter serverWriter = new PrintWriter(socket.getOutputStream(), true);
                    InetAddress address = InetAddress.getLocalHost();
                    String serverIP = address.getHostAddress();
                    serverWriter.println("begin");
                    if (!serverReader.readLine().startsWith("ok")) {
                        errors.add("error DMTP");
                    }
                    serverWriter.println("to " + sender);
                    if (!serverReader.readLine().startsWith("ok")) {
                        errors.add("error DMTP");
                    }
                    serverWriter.println("from " + "mailer@" + serverIP);
                    if (!serverReader.readLine().startsWith("ok")) {
                        errors.add("error DMTP");
                    }
                    serverWriter.println("data " + errors.getFirst());
                    if (!serverReader.readLine().startsWith("ok")) {
                        errors.add("error DMTP");
                    }
                    serverWriter.println("send");
                    if (!serverReader.readLine().startsWith("ok")) {
                        errors.add("error DMTP");
                    }
                    serverWriter.println("quit");
                    if (!serverReader.readLine().startsWith("ok")) {
                        errors.add("error DMTP");
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException("Error while communicating with Mailbox ", e);

                } finally {
                    try {
                        if (socket != null) {
                            socket.close();
                        }
                    } catch (IOException exception) {
                        exception.printStackTrace();
                    }
                }
            }
        }
    }

    private String[] getDomainAddr(String domain, INameserverRemote nameserverRemote) throws RemoteException {
        String[] split = domain.split("\\.");
        INameserverRemote nextNameServer = nameserverRemote;

        for (int i = split.length - 1; i > 0; --i) {
            nextNameServer = nextNameServer.getNameserver(split[i]);
        }
        String addr = nextNameServer.lookup(split[0]);
        return addr.split(":");
    }


    public void stopForwarding() {
        interrupt();
    }
}


