package dslab.ConsoleInputMonitor;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.monitoring.MonitoringServer;
import dslab.util.Config;

import java.io.IOException;

public class ConsoleInputMonitorMonitoringServer extends Thread implements Runnable {
    private MonitoringServer server;
    private Config config;
    private Shell shell;


    public ConsoleInputMonitorMonitoringServer(MonitoringServer server) {
        this.server = server;
        shell = new Shell(server.getIn(), server.getOut());
        shell.register(this);

    }

    @Override
    public void run() {

        shell.run();

    }

    @Command
    private void shutdown() throws IOException {
        server.shutdown();

        throw new StopShellException();

    }

    @Command
    private void addresses() {
        server.addresses();
    }

    @Command
    private void servers() {
        server.servers();
    }

}
