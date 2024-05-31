package dslab.nameserver;

import java.io.InputStream;
import java.io.PrintStream;
import java.rmi.AlreadyBoundException;
import java.rmi.NoSuchObjectException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Logger;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.util.Config;

public class Nameserver implements INameserver {

    private String componentId;
    private Config config;
    private InputStream in;
    private PrintStream out;
    private INameserverRemote remoteNameServer;
    private INameserverRemote remoteNameServerObject;
    private boolean root;
    private Registry registry;
    private Shell shell;


    /**
     * Creates a new server instance.
     *
     * @param componentId the id of the component that corresponds to the Config resource
     * @param config      the component config
     * @param in          the input stream to read console input from
     * @param out         the output stream to write console output to
     */
    public Nameserver(String componentId, Config config, InputStream in, PrintStream out) {
        this.componentId = componentId;
        this.config = config;
        this.in = in;
        this.out = out;
        root = !config.containsKey("domain");
        remoteNameServerObject = new NameserverRemote();
        this.shell = new Shell(in, out);
        shell.register(this);
        shell.setPrompt("---");
    }

    @Override
    public void run() {
        if (root) {
            try {
                registry = LocateRegistry.createRegistry(config.getInt("registry.port"));
                remoteNameServer = (INameserverRemote) UnicastRemoteObject.exportObject(remoteNameServerObject, 0);
                registry.bind(config.getString("root_id"), remoteNameServer);
            } catch (RemoteException e) {
                throw new RuntimeException("Error while starting server");
            } catch (AlreadyBoundException e) {
                throw new RuntimeException("Error while binding object");
            }


        } else {
            try {
                remoteNameServer = (INameserverRemote) UnicastRemoteObject.exportObject(remoteNameServerObject, 0);
                Registry registry = LocateRegistry.getRegistry(config.getString("registry.host"), config.getInt("registry.port"));
                INameserverRemote root = (INameserverRemote) registry.lookup(config.getString("root_id"));
                root.registerNameserver(config.getString("domain"), remoteNameServer);
            } catch (NotBoundException |  InvalidDomainException e) {
                throw new RuntimeException(e);
            } catch (RemoteException e) {
                throw new RuntimeException("Error while starting server");
            } catch (AlreadyRegisteredException e){
                throw new RuntimeException("Server is registered");
            }
        }
        shell.run();

    }

    @Override
    @Command
    public void nameservers() throws RemoteException {
        List<String> nameservers = remoteNameServerObject.getNameServers();
        printServers(nameservers);
    }

    @Override
    @Command
    public void addresses() throws RemoteException {
        List<String> mailBoxServers = remoteNameServerObject.getMailBoxServers();
        printServers(mailBoxServers);
    }

    private void printServers(List<String> servers) {
        if (servers.isEmpty()) {
            out.println("No nameservers found.");
            return;
        }

        servers.sort(Comparator.naturalOrder());

        int index = 1;
        for (String nameserver : servers) {
            out.printf("%d. %s%n", index++, nameserver);
        }
    }

    @Override
    @Command
    public void shutdown() {

        try {
            UnicastRemoteObject.unexportObject(remoteNameServerObject, false);
        } catch (NoSuchObjectException e) {
            throw new RuntimeException(e);
        }

        if (root) {
            try {
                registry.unbind(config.getString("root_id"));
                UnicastRemoteObject.unexportObject(registry, false);
            } catch (RemoteException | NotBoundException e) {

            }
        }
        throw new StopShellException();
    }

    public static void main(String[] args) throws Exception {
        INameserver component = ComponentFactory.createNameserver(args[0], System.in, System.out);
        component.run();
    }


}
