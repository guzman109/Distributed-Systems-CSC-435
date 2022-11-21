/* 
 * Name: Carlos Guzman
 * Date: 09/14/2022
 * 
 * Java Version: 18.0.2.1
 * 
 * Compilation: javac JokeServer.java
 * 
 * Instructions: optional parameter secondary sets up the server on its secondary port.
 * Examples: 
 *      >java JokeServer
 *      >java JokeServer secondary
 */
import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

public class JokeServer {
    public static void main(String args[]) throws IOException {
        int q_len = 6;
        int port = 4545; //Default Port Number
        boolean useSecondary = false;

        // Change port number to secondary
        if (args.length == 1) {
            useSecondary = args[0].equals("secondary");
            if (useSecondary)
                port = 4546;
        }
        
        // Initialize the Joke List and Proverb List
        JokeList.init();
        ProverbList.init();

        // Set up the server to list to admin threads
        AdminConnections AC = new AdminConnections(useSecondary);
        Thread thread = new Thread(AC);
        thread.start();

        // Set up the server to listen to clients
        Socket sock;

        ServerSocket serverSock = new ServerSocket(port, q_len, InetAddress.getByName("localhost"));

        System.out.println
            ("Carlos Guzman's Joke Server 6.9 starting up, listening at {Port:  " + port + "}.\n");
        
        HashMap<String, Client> clientList = new HashMap<String, Client>();
        // Open a socket every time a client invokes server
        while (true) {
            sock = serverSock.accept();
            ClientWorker worker = new ClientWorker(sock);
            clientList = worker.getClient(clientList);
            worker.start();
        }
        
    }
}

class ServerMode {
    // Static class to change the mode of the server from either joke to proverb
    private static int mode = -1;
    public static void toggleMode() {
        mode *= (-1);
    }
    public static int getMode() {
        return mode;
    }
}

class ClientWorker extends Thread {
    Socket sock;
    Client client;

    ClientWorker (Socket s) {
        sock = s;
    }

    /*
     * This function checks if a client has been created and in a list of clients in order to keep
     * track of conversations.
     */
    public HashMap<String, Client> getClient(HashMap<String, Client> list) {
        BufferedReader in = null;
        try {
            // Read the username of the user
            in = new BufferedReader (new InputStreamReader(sock.getInputStream()));
            String userName = in.readLine();

            if (list.containsKey(userName)) {
                // Client has already connected to server
                client = list.get(userName);
            }
            else {
                // Client has never connected to server
                client = new Client(userName);
                list.put(userName, client);
            } 
        } catch (IOException e) { 
            System.out.println("Server read error.");
        }

        return list;
    }

    public void run() {
        PrintStream out = null;
        // BufferedReader in = null;

        try {
            out = new PrintStream (sock.getOutputStream());
            // in = new BufferedReader (new InputStreamReader(sock.getInputStream()));
            
            try {
                // Sent the proper response to the client (either Joke or Proverb)
                out.println(client.getResponse());
            } catch (IOError e) { 
                System.out.println("Server read error");
            }
            sock.close();
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class AdminWorker extends Thread {
    Socket sock;

    AdminWorker (Socket s) {
        sock = s;
    }

    public void run() {
        PrintStream out = null;

        try {
            out = new PrintStream (sock.getOutputStream());
            
            try {
                // Admin wants to change server mode.
                ServerMode.toggleMode();
                System.out.println("Server Mode: " + (ServerMode.getMode() < 0 ? "Joke" : "Proverb"));

                // Send the server mode to the admin
                out.println("Server Mode: " + (ServerMode.getMode() < 0 ? "Joke" : "Proverb"));
            } catch (IOError e) { 
                System.out.println("Server read error");
            }
            sock.close();
        } catch (IOException ioe) {
            System.out.println(ioe);
        }
    }
}

class AdminConnections implements Runnable {
    private static boolean secondary;
    public AdminConnections(boolean useSecondary) { secondary = useSecondary; }

    public void run() {
        int q_len = 6;
        int port = 5050; // Default port for admin connections

        if (secondary)
            port = 5051; // Default port for secondary server from admin

        Socket sock;

        try {
            ServerSocket serverSock = new ServerSocket(port, q_len);
            while (true) {
                // Accept the connection and run the worker
                sock = serverSock.accept();
                new AdminWorker(sock).run();
            }
        } catch (IOException ioe) {
            System.out.println(ioe);
        }

        
    }

}

final class JokeList {
    /*
     * This class holds the jokes to send to each client. It also keeps track which joke has been sent to the client.
     */
    private static ArrayList<String> queue = new ArrayList<String>();
    private static String[] order = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}; // Used to keep track of the order the jokes have been sent.

    public static void init() {
        queue.add("Why do we tell actors to “break a leg? Because every play has a cast.");
        queue.add("What does a nosy pepper do? Gets jalapeño business!");
        queue.add("What do you call a fake noodle? An impasta.");
        queue.add("What did the pirate say when he turned 80? Aye matey.");
        queue.add("What did the left eye say to the right eye? Between you and me, something smells.");
        queue.add("What do you call a magic dog? A labracadabrador.");
        queue.add("What is an astronaut’s favorite part on a computer? The space bar.");
        queue.add("Did you hear about the two people who stole a calendar? They each got six months.");
        queue.add("Why did the Oreo go to the dentist? Because he lost his filling.");
        queue.add("Why aren’t koalas actual bears? They don’t meet the koalafications.");
    }
    public static int length() { return queue.size(); }

    public static String getJoke(int i) { return queue.get(i); }
    public static String getOrder(int n) { return "J"+order[n]; }
}

final class ProverbList {    
    /*
    * This class holds the proverbs to send to each client. It also keeps track which proverb has been sent to the client.
    */
    private static ArrayList<String> queue = new ArrayList<String>();
    private static String[] order = {"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}; // Used to keep track of the order the jokes have been sent.


    public static void init() {
        queue.add("All that glitters is not gold.");
        queue.add("A picture is worth a thousand words.");
        queue.add("All good things come to an end.");
        queue.add("Beggars can’t be choosers.");
        queue.add("A journey of a thousand miles begins with a single step.");
        queue.add("A bird in the hand is worth two in the bush.");
        queue.add("Actions speak louder than words.");
        queue.add("An apple a day keeps the doctor away.");
        queue.add("A stitch in time saves nine.");
        queue.add("Every dog has its day.");
    }

    public static int length() { return queue.size(); }

    public static String getProverb(int i) { return queue.get(i); }
    public static String getOrder(int n) { return "P"+order[n]; }
}

class Client {
    /*
     * This class keeps track of each client that has connected to the server. This class is then added 
     * to a list of clients.
     */

    String userName;
    private ArrayList<Integer> currentProverb;
    private ArrayList<Integer> currentJoke;
    private int proverbOrder = 0;
    private int jokeOrder = 0;

    Client (String s) { 
        userName = s;
        currentProverb = new ArrayList<Integer>(); //Keep track of the list of the proverbs to send
        currentJoke = new ArrayList<Integer>(); //Keep track of the list of the jokes to send

        // Initialize the order to send the jokes
        for (int i = 0; i < JokeList.length(); i++) {
            currentJoke.add(i);
        }
        randomizeJokes(); // randomize them

        // Initialize the order to send the proverbs
        for (int i = 0; i < ProverbList.length(); i++) {
            currentProverb.add(i);
        }
        randomizeProverbs(); //randomize them
    }

    private void randomizeJokes() {
        // Just shuffle the list randomly
        Collections.shuffle(currentJoke);
    }

    private void randomizeProverbs() {
        // Just shuffle the list randomly
        Collections.shuffle(currentProverb);
    }

    public String getOrder() {
        // Return the current order at which the joke has been sent. (A, B, C, D, etc.)
        if (ServerMode.getMode() < 0)
            return JokeList.getOrder(jokeOrder);
        else 
            return ProverbList.getOrder(proverbOrder);
    }

    public String getResponse() {

        String response;

        if (ServerMode.getMode() < 0) {
            // Server is in joke mode
            
            // Get the joke and formulate the proper response
            response = JokeList.getOrder(jokeOrder) + " " + userName + ": " + JokeList.getJoke(currentJoke.get(jokeOrder));  
            jokeOrder++;

            if (jokeOrder == JokeList.length()) {
                // All the jokes have been sent once. Time to shuffle the list
                System.out.println("JOKE CYCLE COMPLETED");
                jokeOrder = 0;
                randomizeJokes();
            }
        }
        else {
            // Server is in proverb mode
            
            // Get the proverb and formulate the proper response
            response = ProverbList.getOrder(proverbOrder) + " " + userName + ": " + ProverbList.getProverb(currentProverb.get(proverbOrder)); 
            proverbOrder++;

            if (proverbOrder == ProverbList.length()) {
                // All the proverbs have been sent once. Time to shuffle the list
                System.out.println("PROVERB CYCLE COMPLETED");
                proverbOrder = 0;
                randomizeProverbs();
            }
        }
         return response;
    }

}
