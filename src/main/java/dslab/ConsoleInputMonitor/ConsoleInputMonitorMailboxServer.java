package dslab.ConsoleInputMonitor;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.mailbox.MailboxServer;
import dslab.transfer.TransferServer;
import dslab.util.Config;

import java.io.IOException;

public class ConsoleInputMonitorMailboxServer extends Thread implements Runnable {
    private MailboxServer server;
    private Config config;
    private Shell shell;
    private String loggedInUser = null;

    public ConsoleInputMonitorMailboxServer(MailboxServer server) {
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
}
