package dslab;

import dslab.mailbox.MailboxServer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class DMAP {
    private String username;
    private String password;
    private boolean secure = false;
    private String componentID;
    private PrivateKey privateKey;
    private String clientChallenge;
    private SecretKey secretKey;
    private IvParameterSpec ivParameter;
    private boolean rsa = false;
    private boolean aes = false;

    private MailboxServer ms;

    public DMAP(MailboxServer ms, String componentID) {
        this.ms = ms;
        this.componentID = componentID;
    }

    public DMAP processCommand(String inputLine, PrintWriter output, Map<String, String> username_password)
        throws Exception {
        if(rsa) {
            inputLine = decrypt_aes(inputLine);
        }
        if (inputLine.startsWith("login")) {
            String[] parts = inputLine.split(" ");
            if (parts.length != 3) {
                System.out.println("Invalid login command. Usage: login <username> <password>");
            } else {
                String usernameTest = parts[1];
                String passwordTest = parts[2];
                switch (authenticateUser(usernameTest, passwordTest, username_password)) {
                    case 0:
                        if (aes) {
                            output.println(encrypt_aes("ok"));
                        } else {
                            output.println("ok");
                        }
                        username = usernameTest;
                        password = passwordTest;
                        return this;
                    case 1:
                        if (aes) {
                            output.println(encrypt_aes("error unknown user"));
                        } else {
                            output.println("error unknown user");
                        }
                        break;
                    case 2:
                        if (aes) {
                            output.println(encrypt_aes("error wrong password"));
                        } else {
                            output.println("error wrong password");
                        }
                        break;
                }
            }
        } else if (inputLine.startsWith("list")) {
            if (username != null && password != null) {
                System.out.println(emailsToString(ms.getEmails(username, -1)));
                output.println(emailsToString(ms.getEmails(username, -1)));
            } else {
                if (aes) {
                    output.println(encrypt_aes("login first"));
                } else {
                    output.println("login first");
                }
            }
        } else if (inputLine.startsWith("startsecure")) {
            secure = true;
            output.println("ok " + componentID);
        } else if (secure) {
            File key_file = new File("keys/server/" + componentID + ".der");
            byte[] privateKeyFile_bytes = Files.readAllBytes(key_file.toPath());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyFile_bytes));
            String decrypted_line = decrypt_rsa(inputLine, privateKey);
            String[] decrypted_line_components = decrypted_line.split(" ");
            clientChallenge = decrypted_line_components[1];
            byte[] secretKey_bytes = decode(decrypted_line_components[2]);
            secretKey = new SecretKeySpec(secretKey_bytes, "AES");
            ivParameter = new IvParameterSpec(decode(decrypted_line_components[3]));

            output.println(encrypt_aes ("ok " + clientChallenge));
            secure = false;
            rsa = true;
        } else if (inputLine.equals("ok") && !aes) {
            aes = true;
        } else if (inputLine.startsWith("show")) {
            try {
                long id = Long.parseLong(inputLine.substring(5).trim());
                ArrayList<DMTP> email = ms.getEmails(username, id);
                if (email != null) {
                    System.out.println(oneEmailToString(email.get(0)));
                    output.println(oneEmailToString(email.get(0)));
                } else {
                    if(aes) {
                        output.println(encrypt_aes("error unknown message id"));
                    } else {
                        output.println("error unknown message id");
                    }
                }
            } catch (NumberFormatException e) {
                if(aes) {
                    output.println(encrypt_aes("error invalid id format"));
                } else {
                    output.println("error invalid id format");
                }
            }
        } else if (inputLine.startsWith("delete")) {
            try {
                long id = Long.parseLong(inputLine.substring(7).trim());
                if (ms.deleteEmailWithId(username, id)) {
                    if(aes) {
                        output.println(encrypt_aes("ok"));
                    } else {
                        output.println("ok");
                    }
                } else {
                    if(aes) {
                        output.println(encrypt_aes("error unknown message id"));
                    } else {
                        output.println("error unknown message id");
                    }
                }
            } catch (NumberFormatException e) {
                if(aes) {
                    output.println(encrypt_aes("error invalid id format"));
                } else {
                    output.println("error invalid id format");
                }
            }
        } else if (inputLine.startsWith("logout")) {
            username = null;
            password = null;
            if(aes) {
                output.println(encrypt_aes("ok"));
            } else {
                output.println("ok");
            }
        } else if (inputLine.startsWith("quit")) {
            if(aes) {
                output.println(encrypt_aes("ok bye"));
            } else {
                output.println("ok bye");
            }
        } else {
            if(aes) {
                output.println(encrypt_aes("error"));
            } else {
                output.println("error");
            }
        }

        return this;
    }

    private String decrypt_aes(String inputLine) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, this.secretKey, this.ivParameter);
        byte[] cipher_bytes = cipher.doFinal(decode(inputLine));
        return new String(cipher_bytes);
    }

    private String decrypt_rsa(String inputLine, PrivateKey privateKey) throws Exception {
        byte[] encryptedBytes = decode(inputLine);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    private static byte[] decode(String inputLine) {
        return Base64.getDecoder().decode(inputLine);
    }

    private String encrypt_aes(String inputLine) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, this.ivParameter);
        byte[] cipher_bytes = cipher.doFinal(inputLine.getBytes());
        return Base64.getEncoder().encodeToString(cipher_bytes);
    }

    private int authenticateUser(String username, String password, Map<String, String> usernamePasswordMap) {
        String storedPassword = usernamePasswordMap.get(username);
        if (storedPassword == null) {
            return 1;
        } else if (!storedPassword.equals(password)) {
            return 2;
        }
        return 0;
    }

    private String emailsToString(ArrayList<DMTP> emails) throws Exception {
        StringBuilder toRet = new StringBuilder();
        if (emails != null) {
            for (DMTP email : emails) {
                if(aes) {
                    toRet.append(encrypt_aes(email.getEmailId() + " " + email.getSender() + " " + email.getSubject() + "\n"));
                } else {
                    toRet.append(email.getEmailId()).append(" ").append(email.getSender()).append(" ").append(email.getSubject()).append("\n");
                }
            }
            String okay;
            if(aes) {
                okay = encrypt_aes("ok");
            } else {
                okay = "ok";
            }
            toRet.append(okay).append("\n");
            return toRet.toString();
        }
        return "";
    }

    private String oneEmailToString(DMTP email) throws Exception {
        String toRet = "";
        if(aes) {
            toRet += encrypt_aes("from " + email.getSender());
            toRet += encrypt_aes("\n" + "to " + email.recipientsToString());
            toRet += encrypt_aes("\n" + "subject " + email.getSubject());
            toRet += encrypt_aes("\n" + "data " + email.getData());
            toRet += encrypt_aes("\n" + "hash " + email.getHash());
        } else {
            toRet += "from " + email.getSender();
            toRet += "\n" + "to " + email.recipientsToString();
            toRet += "\n" + "subject " + email.getSubject();
            toRet += "\n" + "data " + email.getData();
            toRet += "\n" + "hash " + email.getHash();
        }
        return toRet;
    }

}