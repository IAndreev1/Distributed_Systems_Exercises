package dslab.monitoring;

import dslab.ComponentFactory;
import dslab.ConsoleInputMonitor.ConsoleInputMonitorMonitoringServer;
import dslab.util.Config;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;

public class MonitoringServer implements IMonitoringServer {

    private String componentId;
    private Config config;
    private InputStream in;
    private PrintStream out;
    private DatagramSocket datagramSocket;
    private Map<String, Integer> emailAddresses = new HashMap<>();
    private Map<String, Integer> servers = new HashMap<>();


    /**
     * Creates a new server instance.
     *
     * @param componentId the id of the component that corresponds to the Config resource
     * @param config      the component config
     * @param in          the input stream to read console input from
     * @param out         the output stream to write console output to
     */
    public MonitoringServer(String componentId, Config config, InputStream in, PrintStream out) {
        this.componentId = componentId;
        this.config = config;
        this.in = in;
        this.out = out;

    }

    @Override
    public void run() {
        ListenerThread thread = null;
        try {
            new ConsoleInputMonitorMonitoringServer(this).start();
            datagramSocket = new DatagramSocket(config.getInt("udp.port"));
            thread = new ListenerThread(datagramSocket, this);
            thread.start();
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot listen on UDP port.", e);
        }
    }

    public void update(String server, String email) {
        if (emailAddresses.get(email) != null) {
            emailAddresses.put(email, emailAddresses.get(email) + 1);
        } else {
            Integer count = 1;
            emailAddresses.put(email, count);
        }
        if (servers.get(server) != null) {
            servers.put(server, servers.get(server) + 1);
        } else {
            Integer count = 1;
            servers.put(server, count);
        }
    }

    @Override

    public void addresses() {
        StringBuilder toPrint = new StringBuilder();
        for (Map.Entry<String, Integer> address : emailAddresses.entrySet()) {
            toPrint.append(address.getKey()).append(" ").append(address.getValue()).append("\n");
        }
        out.println(toPrint);
    }

    public InputStream getIn() {
        return in;
    }

    public PrintStream getOut() {
        return out;
    }

    @Override
    public void servers() {
        StringBuilder toPrint = new StringBuilder();
        for (Map.Entry<String, Integer> server : servers.entrySet()) {
            toPrint.append(server.getKey()).append(" ").append(server.getValue()).append("\n");
        }
        out.println(toPrint);
    }

    @Override
    public void shutdown() {

        if (datagramSocket != null) {
            datagramSocket.close();
        }

    }

    public static void main(String[] args) throws Exception {
        IMonitoringServer server = ComponentFactory.createMonitoringServer(args[0], System.in, System.out);
        server.run();
    }

}

class ListenerThread extends Thread {

    private DatagramSocket datagramSocket;
    private MonitoringServer ms;

    public ListenerThread(DatagramSocket datagramSocket, MonitoringServer ms) {
        this.datagramSocket = datagramSocket;
        this.ms = ms;

    }

    @Override
    public void run() {
        byte[] buffer;
        DatagramPacket packet;
        try {
            while (true) {
                buffer = new byte[1024];
                packet = new DatagramPacket(buffer, buffer.length);
                datagramSocket.receive(packet);

                String request = new String(packet.getData());


                System.out.println("Received request-packet from client: " + request);


                String[] parts = request.split(" ");
                String host_port = parts[0].trim();
                String email = parts[1].trim();
                ms.update(host_port, email);


            }

        } catch (SocketException e) {
            //ignoring
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

    }


}
