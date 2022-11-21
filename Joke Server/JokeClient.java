/* 
 * Name: Carlos Guzman
 * Date: 09/14/2022
 * 
 * Java Version: 18.0.2.1
 * 
 * Compilation: javac JokeClient.java
 * 
 * Instructions: optional first parameter [IP address to connect to server], optional second parameter [IP address to connect to server]
 * Examples: 
 *      >java JokeClient    (Connects to server at default address)
 *      >java JokeClient localhost  (Connects to server at the local host address)
 *      >java JokeClient 120.149.40.21 (Connects to server at the provided address)
 *      >java JokeClient localhost 120.149.40.21 (Connects to the first server at localhost address and second server at the provided address (120.149.40.21))
 */
import java.io.*;
import java.net.*;

public class JokeClient{
    static boolean connected = false;

    public static void main (String args[]) {
        String primaryServerName = "localhost"; //default server primary address
        String secondaryServerName = "localhost"; //default server secondary address

        // Default ports to each server
        int primaryPort = 4545; 
        int secondaryPort = 4546;

        boolean useSecondary = false; //Used to check if a secondary server is to be connected to
        int toggleServers = 1;  // Toggles which server to use


        // Finds the name of the server
        if (args.length == 1) {
            primaryServerName = args[0]; // get the primary server name from arguments
        }
        else if (args.length == 2) {
            primaryServerName = args[0]; //get the primary server name from arguments
            secondaryServerName = args[1]; //get the secondary server name from arguments
            useSecondary = true; //secondary server at use
        }

        // print out the servers the client is connected to 
        System.out.println("Server One: " + primaryServerName + ", port " + primaryPort);
        if (useSecondary)
            System.out.println("Server Two: " + secondaryServerName + ", port " + secondaryPort);


        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        try {
            String userName, userInput;
            System.out.print("Please enter a user name.\n");
            userName = in.readLine();
            System.out.println("User Name: " + userName);

            // Continuously prompt user to either change server or get response from server.
            do {
                System.out.println("Get Response, Change server with (\'s\') or Quit (\"quit\")?");
                System.out.flush(); //Flush the buffer before user input
    
                userInput = in.readLine();

                // Toggle between servers if the second server is opened and user requests it.
                if (userInput.equals("s") && useSecondary) {
                    toggleServers *= (-1); // 1 == primary Server, (-1) == secondaryServer
                    System.out.println("Now communicating with: " + 
                        (toggleServers == 1 ? primaryServerName : secondaryServerName) +
                        " port " + (toggleServers == 1 ? primaryPort : secondaryPort));
                }
                else if (userInput.equals("s") && !useSecondary) {
                    System.out.println("No secondary server being used");
                }
                else if (userInput.indexOf("quit") < 0) {
                    // User wants a response from toggled server.
                    String serverName = (toggleServers == 1 ? primaryServerName : secondaryServerName); // get the server name to use
                    int port = (toggleServers == 1 ? primaryPort : secondaryPort);//get the port to use (either primary or secondary)
                    getResponse(serverName, port, userName, toggleServers);
                }
            } while (userInput.indexOf("quit") < 0);
            System.out.println("Cancelled by user request."); //User entered "quit"
        } catch (IOException x) { x.printStackTrace(); } //print call stack if an error occurs 
    }

    static void getResponse (String serverName, int port, String userName, int secondary) {
        Socket sock;
        BufferedReader fromServer;
        PrintStream toServer;
        String textFromServer;

        try {
            sock = new Socket(serverName, port); // Open a socket at port 1565
            fromServer = new BufferedReader(new InputStreamReader(sock.getInputStream())); //Buffer to append response from server
            toServer = new PrintStream(sock.getOutputStream()); //Buffer to send message to server

            // Send user name to server
            toServer.println(userName); 
            toServer.flush();

            // Read response from server
            textFromServer = fromServer.readLine();
            if (textFromServer != null)
                System.out.println((secondary == (-1) ? "<S2> " : "") + textFromServer + "\n"); // Formulate response if its coming from secondary server
            sock.close();
        } catch (IOException x) {
            System.out.println("Socket error.");
            x.printStackTrace();
        }
    }
}