package org.example;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.example.AlphabetManager.RESET_SYMBOL;
import static org.example.AlphabetManager.RESTRICTED_SYMBOL;

public class NetworkManager {

    public static final String ALPHABET = "alphabet";
    public static final String STOP = "stop";
    public static final String COUNTER_EXAMPLE = "checkCounterExample";
    public static final String CLOSE_CONNECT = "closeConnect";
    private enum MessageType {
        SYSTEM_MESSAGE,
        LEARNLIB_MESSAGE,
        QUERY_MESSAGE
    }
    public ServerSocket serverSocket;
    private final Socket clientSocket;
    private final OutputStream out;
    private final InputStream in;

    public NetworkManager(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        LogManager.logger.logEvent("Waiting for the client to connect....");
        clientSocket = serverSocket.accept();
        clientSocket.setTcpNoDelay(true);
        clientSocket.setSoTimeout(0);
        out = new DataOutputStream(clientSocket.getOutputStream());
        in = new DataInputStream(clientSocket.getInputStream());
        LogManager.logger.logEvent("Client Connected: " + clientSocket.getInetAddress() + ": " + clientSocket.getPort());
        sendMessage(MessageType.SYSTEM_MESSAGE, ALPHABET);
    }

    public String sendQuery(String query) throws IOException {
        if (Objects.equals(query, RESET_SYMBOL))
            return new String(sendMessage(MessageType.LEARNLIB_MESSAGE, query));
        else
            return new String(sendMessage(MessageType.QUERY_MESSAGE, query));
    }

    private byte[] sendMessage(MessageType type, String message) throws IOException {
        byte[] messageBytes = message.getBytes();
        byte[] totalBytes = new byte[1 + messageBytes.length];
        totalBytes[0] = (byte) type.ordinal();
        System.arraycopy(messageBytes, 0, totalBytes, 1, messageBytes.length);
        out.write(totalBytes);
        out.flush();
        if (type == MessageType.SYSTEM_MESSAGE)
            LogManager.logger.logEvent("Sent system message (" + message + ") successfully!");
        return receiveMessage(type);
    }

    private byte[] receiveMessage(MessageType  type) throws IOException {
        // Read byte array
        byte[] receiveMessage = new byte[1024];
        int bytesReceive = in.read(receiveMessage);
        byte receiveType = receiveMessage[0];
        byte[] messageBytes = new byte[bytesReceive - 1];
        System.arraycopy(receiveMessage, 1, messageBytes, 0, bytesReceive - 1);
        String message = new String(messageBytes);

        // Process the message
        if (receiveType > type.ordinal()) {
            LogManager.logger.error("Received lower type message");
            return STOP.getBytes();
        }
        switch (MessageType.values()[receiveType]) {
            case SYSTEM_MESSAGE:
                LogManager.logger.logEvent("System message: " + message);
                break;
            case LEARNLIB_MESSAGE:
            case QUERY_MESSAGE:
                break;
            default:
                LogManager.logger.error("Wrong type message");
        }
        return message.getBytes();
    }

    public List<String> checkCounterExample(List<String> symbols, boolean useNoElement) throws IOException {
        sendMessage(MessageType.LEARNLIB_MESSAGE, COUNTER_EXAMPLE);
        List<String> result = new ArrayList<>();
        boolean isNoElement = false;
        for (String symbol : symbols) {
            if (Objects.equals(symbol, RESET_SYMBOL)) {
                result.add(sendQuery(symbol));
            } else {
                String re;
                if (useNoElement && isNoElement) {
                    re = RESTRICTED_SYMBOL;
                    LogManager.logger.logEvent("Reply by " + re);
                } else {
                    re = sendQuery(symbol);
                    if (Objects.equals(re, RESTRICTED_SYMBOL)) {
                        isNoElement = true;
                    }
                }
                result.add(re);
            }
        }
        return result;
    }

    public void closeConnection() {
        try {
            sendMessage(MessageType.SYSTEM_MESSAGE, CLOSE_CONNECT);
            clientSocket.close();
            serverSocket.close();
            out.close();
            in.close();
            LogManager.logger.logEvent("Close the connection");
        } catch (IOException e) {
            LogManager.logger.error("Error while closing connection: " + e.getMessage());
        }
    }
}
