package dslab.client;

import java.io.*;
import java.net.Socket;
import java.net.ProtocolException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import at.ac.tuwien.dsg.orvell.Shell;
import at.ac.tuwien.dsg.orvell.StopShellException;
import at.ac.tuwien.dsg.orvell.annotation.Command;
import dslab.ComponentFactory;
import dslab.security.AesCipher;
import dslab.util.Config;
import dslab.util.Keys;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class MessageClient implements IMessageClient, Runnable {

    final private Shell shell;
    final private Config config;
    private String email;
    private Socket socketDmap;
    private AesCipher aesCipher = null;
    private BufferedReader dmapReader;
    private PrintWriter dmapWriter;
    private final Log LOG = LogFactory.getLog(MessageClient.class);

    /**
     * Creates a new client instance.
     *
     * @param componentId the id of the component that corresponds to the Config resource
     * @param config the component config
     * @param in the input stream to read console input from
     * @param out the output stream to write console output to
     */
    public MessageClient(String componentId, Config config, InputStream in, PrintStream out) {
        this.config = config;
        shell = new Shell(in, out);
        shell.register(this);
        shell.setPrompt(componentId + "> ");
    }

    @Override
    public void run() {
        this.email = config.getString("transfer.email");
        startsecure();
        shell.run();
    }

    private void startsecure() {
        try {
            socketDmap = new Socket(config.getString("mailbox.host"), config.getInt("mailbox.port"));
            dmapReader = new BufferedReader(new InputStreamReader(socketDmap.getInputStream()));
            dmapWriter = new PrintWriter(socketDmap.getOutputStream());

            String firstResponse = dmapReader.readLine();
            if (!firstResponse.startsWith("ok DMAP2.0")) {
                throw new ProtocolException("Bad response");
            }

            dmapWriter.println("startsecure");
            dmapWriter.flush();

            String response = dmapReader.readLine();
            if (!response.startsWith("ok")) {
                throw new ProtocolException(response);
            }

            String componentId = response.substring(3);

            // Challenge generation
            SecureRandom random = new SecureRandom();
            byte[] challengeBytes = new byte[32];
            random.nextBytes(challengeBytes);
            String challenge = Base64.getEncoder().encodeToString(challengeBytes);

            // Key generation
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey key = keyGenerator.generateKey();
            String keyString = Base64.getEncoder().encodeToString(key.getEncoded());

            // IV generation
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            String ivString = Base64.getEncoder().encodeToString(iv);

            // Challenge response generation with RSA public key
            String challengeMessage = String.format("ok %s %s %s", challenge, keyString, ivString);

            PublicKey publicKey = Keys.readPublicKey(new File(String.format("keys/client/%s_pub.der", componentId)));
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(challengeMessage.getBytes());
            String message = Base64.getEncoder().encodeToString(encryptedBytes);

            dmapWriter.println(message);
            dmapWriter.flush();

            String challengeAesEnc = dmapReader.readLine();

            aesCipher = new AesCipher(key, iv);
            String challengeResponse = aesCipher.decrypt(challengeAesEnc).split("\\s")[1];
            if (!challengeResponse.equals(challenge)) {
                throw new ProtocolException("Bad challenge response");
            }

            // Send ok
            dmapWriter.println(aesCipher.encrypt("ok"));
            dmapWriter.flush();

            LOG.info("Completed handshake");

            String res = sendDmap(String.format("login %s %s", config.getString("mailbox.user"), config.getString("mailbox.password")));
            if (!res.startsWith("ok")) {
                throw new ProtocolException(res);
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            shell.out().println("Couldn't connect to mail server: " + e.getMessage());
            cleanup();
        }
    }

    private String sendDmap(String line) throws IOException {
        if (socketDmap == null || socketDmap.isClosed())
            throw new IOException("socket closed");
        try {
            dmapWriter.println(aesCipher.encrypt(line));
            dmapWriter.flush();

            return aesCipher.decrypt(dmapReader.readLine());
        } catch (Exception e) {
            return "Error while trying to write to server";
        }
    }

    public String hash(String value) {
        File secretKeyFile = new File("keys/hmac.key");
        try {
            SecretKeySpec keySpec = Keys.readSecretKey(secretKeyFile);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySpec);

            byte[] resBytes = mac.doFinal(value.getBytes());
            return Base64.getEncoder().encodeToString(resBytes);
        } catch (Exception e) {
            // Don't catch as invalid setup would make it impossible to use the DMTP2.0 protocol at all
            throw new RuntimeException("Error during hash creation", e);
        }
    }

    @Override
    @Command
    public void inbox() {
        boolean linebreak = false;
        String res;
        try {
            res = sendDmap("list");
        } catch (Exception e) {
            shell.out().println("error");
            return;
        }
        if (!res.endsWith("ok")) {
            shell.out().println("Couldn't read mailbox");
            return;
        }
        String[] lines = res.split("\n");

        for (String line : lines) {
            if (line.equals("ok") || line.isEmpty()) break;
            String number = line.split("\\s")[0];
            String res2;
            try {
                res2 = sendDmap("show " + number);
            } catch (Exception e) {
                shell.out().println("error");
                return;
            }
            if (res2.endsWith("\nok"))
                if (linebreak) shell.out().println();
            linebreak = true;
            shell.out().println("Number: \t" + number);
            shell.out().println(res2.substring(0, res2.length() - 3));
        }
    }

    @Override
    @Command
    public void delete(String id) {
        String res;
        try {
            res = sendDmap("delete " + id);
        } catch (Exception e) {
            shell.out().println("error");
            return;
        }
        shell.out().println(res);
    }

    @Override
    @Command
    public void verify(String id) {
        String res;
        try {
            res = sendDmap("show " + id);
        } catch (Exception e) {
            shell.out().println("error");
            return;
        }
        Pattern p = Pattern.compile("^From: \t\t(?<from>.*)\nTo: \t\t(?<to>.*)\nSubject: \t(?<subject>.*)\nData: \t\t(?<data>.*)\nHash: \t\t(?<hash>.*)\nok$");
        Matcher m = p.matcher(res);
        if (m.find()) {
            String all = String.join("\n", m.group("from"), m.group("to"), m.group("subject"), m.group("data"));
            String hash = m.group("hash");
            shell.out().println(hash(all).equals(hash));
        } else {
            shell.out().println("error could not match regex to string");
        }
    }

    @Override
    @Command
    public void msg(String to, String subject, String data) {
        //formatting to
        List<String> list = Arrays.asList(to.split(","));
        list.replaceAll(String::strip);
        Set<String> addresses = new HashSet<>(list);
        for (String address : addresses) {
            if (address.split("@").length != 2) {
                shell.out().println("Argument of command 'to' must be in the format '<user>@<hostname>, <user1>@<hostname1>, ...'");
                return;
            }
        }
        String toFormat = String.join(",", addresses);
        String all = String.join("\n", email, toFormat, subject, data);

        Socket socket = null;
        try {
            socket = new Socket(config.getString("transfer.host"), config.getInt("transfer.port"));

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                 PrintWriter writer = new PrintWriter(socket.getOutputStream())) {
                send("begin", reader, writer);
                send("from " + email, reader, writer);
                send("to " + toFormat, reader, writer);
                send("subject " + subject, reader, writer);
                send("data " + data, reader, writer);
                send("hash " + hash(all), reader, writer);
                send("send", reader, writer);
                send("quit", reader, writer);
                shell.out().println("ok");
            }
        } catch (ProtocolException e) {
            LOG.info(e.getMessage());
            shell.out().println(e.getMessage());
        } catch (UnknownHostException e) {
            LOG.error(e.getMessage());
            e.printStackTrace();
        } catch (
                SocketException e) {
            LOG.info("Stopping client because socket was closed");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                } catch (IOException e) {
                    LOG.error("Exception during closing of Socket: " + e.getMessage());
                }
            }
            LOG.debug("Socket, reader and writer of client closed.");
        }
    }

    private void send(String line, BufferedReader reader, PrintWriter writer) throws IOException {
        writer.println(line);
        writer.flush();

        String res = reader.readLine();
        if (!res.startsWith("ok")) throw new ProtocolException(res);
    }

    private void cleanup() {
        if (socketDmap != null && !socketDmap.isClosed()) {
            try {
                sendDmap("logout");
                socketDmap.close();
            } catch (IOException e) {
                // Ignored because we cannot handle it
            }
        }
        if (dmapReader != null) {
            try {
                dmapReader.close();
            } catch (IOException e) {
                // Ignored because we cannot handle it
            }
        }
        if (dmapWriter != null) {
            dmapWriter.close();
        }
    }

    @Override
    @Command
    public void shutdown() {
        cleanup();
        throw new StopShellException();
    }

    public static void main(String[] args) throws Exception {
        IMessageClient client = ComponentFactory.createMessageClient(args[0], System.in, System.out);
        client.run();
    }
}
