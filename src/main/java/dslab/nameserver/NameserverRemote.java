package dslab.nameserver;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.rmi.RemoteException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class NameserverRemote implements INameserverRemote {

    private ConcurrentHashMap<String, INameserverRemote> child = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, String> mailBoxServers = new ConcurrentHashMap<>();
    private final static Log logger = LogFactory.getLog(NameserverRemote.class);


    @Override
    public void registerNameserver(String domain, INameserverRemote nameserver) throws RemoteException, AlreadyRegisteredException, InvalidDomainException {
        String[] split = domain.split("\\.");


        //when the domain is final => create NameServer
        if (split.length == 1) {
            logger.info(" Registering nameserver for zone " + "'" + split[0] + "'");
            child.put(split[0], nameserver);
        } else {
            String currentDomain = split[split.length - 1];

            if (child.get(currentDomain) == null) {

                throw new InvalidDomainException("Could not find domain registry in child set" + currentDomain + " of given domain " + domain);
            }
            child.get(currentDomain).registerNameserver(getDomain(split), nameserver);
        }


    }

    @Override
    public void registerMailboxServer(String domain, String address) throws RemoteException, AlreadyRegisteredException, InvalidDomainException {
        String[] split = domain.split("\\.");
        if (split.length == 1) {
            logger.info(" Registering mailbox server " + "'" + split[0] + "'" + " with address " + address);
            mailBoxServers.put(split[0], address);
        } else {
            String currentDomain = split[split.length - 1];

            if (child.get(currentDomain) == null) {

                throw new InvalidDomainException("Could not find domain registry in child set" + currentDomain + " of given domain " + domain);
            }
            child.get(currentDomain).registerMailboxServer(getDomain(split), address);
        }
    }

    @Override
    public INameserverRemote getNameserver(String zone) throws RemoteException {
        for (String domain : child.keySet()) {
            if (domain.equals(zone)) {
                return child.get(domain);
            }
        }
        for (Map.Entry<String, INameserverRemote> remote : child.entrySet()) {
            return remote.getValue().getNameserver(zone);
        }

        throw new RemoteException("Nameserver for zone: " + zone.toLowerCase() + " not found");
    }

    @Override
    public String lookup(String username) throws RemoteException {
        logger.info("Nameserver for '" + username + "' requested by transfer server");
        return mailBoxServers.get(username);
    }

    public List<String> getNameServersOld() throws RemoteException {
        List<String> toReturn = new LinkedList<>();
        for (Map.Entry<String, INameserverRemote> entry : child.entrySet()) {
            toReturn.add(entry.getKey());
            toReturn.addAll(entry.getValue().getNameServers());
        }
        return toReturn;
    }

    @Override
    public List<String> getNameServers() throws RemoteException {
        return new LinkedList<>(child.keySet());
    }

    @Override
    public List<String> getMailBoxServers() throws RemoteException {
        List<String> toReturn = new LinkedList<>();
        for (Map.Entry<String, String> entry : mailBoxServers.entrySet()) {
            toReturn.add(entry.getKey() + " " + entry.getValue());
        }
        return toReturn;
    }

    private String getDomain(String[] DomainSplit) {
        List<String> subdomain = new LinkedList<>(Arrays.asList(DomainSplit));
        subdomain.remove(subdomain.size() - 1);
        return String.join(".", subdomain);
    }
}
