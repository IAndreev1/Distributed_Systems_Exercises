package dslab;

import dslab.util.Keys;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class DMTP {
    private long emailId;
    private ArrayList<String> recipients;
    private String sender;
    private String subject;
    private String data;
    private String hash = "";
    private boolean sent;
    private boolean ended;
    private boolean started;
    private static final String HMAC_KEY_FILE = "keys/hmac.key";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

      public DMTP() {

    }

    public boolean isSent() {
        return sent;
    }

    public boolean isEnded() {
        return ended;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public void setRecipients(ArrayList<String> recipients) {
        this.recipients = recipients;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getSubject() {
        return subject;
    }

    public ArrayList<String> getRecipients() {
        return recipients;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String recipientsToString() {
        StringBuilder toRet = new StringBuilder();
        for (String recipient : recipients) {
            toRet.append(recipient).append(", ");
        }
        return toRet.toString();
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String hash() {
        try {
            Mac mac = initMac();
            byte[] resBytes = mac.doFinal(messageValue().getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(resBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error during hash creation", e);
        }
    }

    private Mac initMac() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        SecretKeySpec keySpec = readSecretKey();
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(keySpec);
        return mac;
    }

    private SecretKeySpec readSecretKey() throws IOException {
        File secretKeyFile = new File(HMAC_KEY_FILE);
        return Keys.readSecretKey(secretKeyFile);
    }

    public String messageValue() {
        List<String> messageList = new ArrayList<>();

        messageList.add(sender);
        messageList.add(String.join(",", recipients));
        messageList.add(subject);
        messageList.add(data);

        return String.join("\n", messageList);
    }

    @Override
    public String toString() {
        return "DMTP{" +
            "recipients=" + recipients +
            ", sender='" + sender + '\'' +
            ", subject='" + subject + '\'' +
            ", data='" + data + '\'' +
            ", hash='" + hash + '\'' +
            '}';
    }

    //Processing the command and return the updated data.
    public DMTP processCommand(String inputLine, PrintWriter output, DMTP protocol) {
        ArrayList<String> recipients = new ArrayList<String>();

        if (inputLine.startsWith("begin")) {
            if (started) {
                output.println("error");
            } else {
                started = true;
                output.println("ok");
            }
        } else if (inputLine.startsWith("to") && started) {
            LinkedList<String> errors = new LinkedList<>();
            String recipientsInLine = inputLine.substring(3);
            String[] recipientArray = recipientsInLine.split(",");
            for (String recipient : recipientArray) {
                if (isValidEmail(recipient.trim())) {
                    recipients.add(recipient.trim());
                } else {
                    errors.add(recipient.trim());
                }
            }
            if (!errors.isEmpty()) {
                output.println("error Invalid recipient email: " + errors.getFirst());
            } else {
                protocol.setRecipients(recipients);
                output.println("ok " + recipients.size());
            }
        } else if (inputLine.startsWith("from")) {

            String sender = inputLine.substring(5);
            if (isValidEmail(sender)) {
                protocol.setSender(sender);
                output.println("ok");
            } else {
                output.println("error Invalid sender email");
            }
        } else if (inputLine.startsWith("subject") && started) {
            String subject = inputLine.substring(8);
            protocol.setSubject(subject);
            output.println("ok");
        } else if (inputLine.startsWith("data") && started) {
            String data = inputLine.substring(5);
            protocol.setData(data);
            output.println("ok");
        } else if (inputLine.startsWith("hash") && started) {
            String hash = inputLine.substring(5);
            protocol.setData(hash);
            output.println("ok");
        } else if (inputLine.startsWith("send") && started) {
            if (protocol.sender == null || protocol.recipients == null || protocol.data == null) {
                output.println("error");
            } else {
                output.println("ok");
                sent = true;
            }
        } else if (inputLine.startsWith("quit") && started) {
            output.println("ok");
            ended = true;
        } else {
            output.println("error");
        }
        return protocol;
    }

    private boolean isValidEmail(String email) {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,100}$";
        return email.matches(emailRegex);
    }

    //Processing the command and return the updated data.
    public DMTP processCommandForMailBox(String inputLine, PrintWriter output, DMTP protocol, String domain, Set<String> acceptedUsers) {
        ArrayList<String> newRecipients = new ArrayList<String>();

        if (inputLine.startsWith("begin")) {
            output.println("ok");
        } else if (inputLine.startsWith("to")) {
            String recipientsInLine = inputLine.substring(3).replace("[", "").replace("]", "");
            String[] recipientArray = recipientsInLine.split(",");
            for (String recipient : recipientArray) {
                String[] recipients = recipient.split("@");
                String userName = recipients[0].trim();
                String recipientDomain = recipients[1].trim();
                if (recipientDomain.equals(domain)) {
                    if (acceptedUsers.contains(userName)) {
                        newRecipients.add(recipient.trim());
                    }
                }
                protocol.setRecipients(newRecipients);
            }
            if (recipients.size() > 0) {
                output.println("ok " + recipients.size());
            } else {
                output.println("error");
            }
        } else if (inputLine.startsWith("from")) {
            String sender = inputLine.substring(5);
            protocol.setSender(sender);
            output.println("ok");
        } else if (inputLine.startsWith("subject")) {
            String subject = inputLine.substring(8);
            protocol.setSubject(subject);
            output.println("ok");
        } else if (inputLine.startsWith("data")) {
            String data = inputLine.substring(5);
            protocol.setData(data);
            output.println("ok");
        } else if (inputLine.startsWith("hash")) {
            String hash = inputLine.substring(5);
            protocol.setData(hash);
            output.println("ok");
        }  else if (inputLine.startsWith("send")) {
            if (protocol.sender == null || protocol.recipients == null || protocol.data == null) {
                output.println("error");
            } else {
                output.println("ok");
                sent = true;
            }
        } else if (inputLine.startsWith("quit")) {
            output.println("ok bye");
            ended = true;
        } else {
            output.println("error");
        }
        return protocol;
    }

    public long getEmailId() {
        return emailId;
    }

    synchronized public void setEmailId(long emailId) {
        this.emailId = emailId;
    }
}
