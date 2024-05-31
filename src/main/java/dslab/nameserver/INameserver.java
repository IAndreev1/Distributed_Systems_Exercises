package dslab.nameserver;

import java.rmi.RemoteException;

/**
 * A Nameserver application.
 *
 * Do not change the existing method signatures!
 */
public interface INameserver extends Runnable {

    /**
     * Starts the server.
     */
    @Override
    void run();

    /**
     * CLI command to report information about each known nameserver (zones) from the perspective of this nameserver.
     */
    void nameservers() throws RemoteException;

    /**
     * CLI command to report information about the handled mailbox servers, containing mail domain and address
     * (IP:port).
     */
    void addresses() throws RemoteException;

    /**
     * CLI command to shut down the server. After this method, all resources should be closed, and the application
     * should terminate.
     */
    void shutdown();

}
