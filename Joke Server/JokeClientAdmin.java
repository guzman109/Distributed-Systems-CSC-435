/* 
 * Name: Carlos Guzman
 * Date: 09/14/2022
 * 
 * Java Version: 18.0.2.1
 * 
 * Compilation: javac JokeClientAdmin.java
 * 
 * Instructions: optional first parameter [IP address to connect to server], optional second parameter [IP address to connect to server]
 * Examples: 
 *      >java JokeClientAdmin    (Connects to server at default address)
 *      >java JokeClientAdmin localhost  (Connects to server at the local host address)
 *      >java JokeClientAdmin 120.149.40.21 (Connects to server at the provided address)
 *      >java JokeClientAdmin localhost 120.149.40.21 (Connects to the first server at localhost address and second server at the provided address (120.149.40.21))
 */
import java.io.*;
import java.net.*;

public class JokeClientAdmin{
    static boolean connected = false;

    public static void main (String args[]) {
        String primaryServerName = "localhost";//default server primary address
        String secondaryServerName = "localhost";//default server secondary address

         // Default ports to each admin server
        int primaryPort = 5050;
        int secondaryPort = 5051;

        boolean useSecondary = false;//Used to check if a secondary server is to be connected to
        int toggleServers = 1;// Toggles which server to use


        // Finds the name of the server
        if (args.length == 1) {
            primaryServerName = args[0];// get the primary server name from arguments
        }
        else if (args.length == 2) {
            primaryServerName = args[0];//get the primary server name from arguments
            secondaryServerName = args[1];//get the secondary server name from arguments
            useSecondary = true;//secondary server at use
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

            // Continuously prompt user to either switch servers or toggle server mode
            do {
                System.out.println("Toggle Server Mode, Change Server (\'s\') or Quit (\"quit\")?");
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
                    // Admin wants to change the server mode
                    String serverName = (toggleServers == 1 ? primaryServerName : secondaryServerName); //get the server name to use (either primary or secondary)
                    int port = (toggleServers == 1 ? primaryPort : secondaryPort); //get the port to use (either primary or secondary)
                    changeServerModeAndGetResponse(serverName, port, toggleServers);
                }
            } while (userInput.indexOf("quit") < 0);

            System.out.println("Cancelled by user request."); //User entered "quit"
        } catch (IOException x) { x.printStackTrace(); } //print call stack if an error occurs 
    }

    static void changeServerModeAndGetResponse (String serverName, int port, int secondary) {
        Socket sock;
        BufferedReader fromServer;
        String textFromServer;

        try {
            sock = new Socket(serverName, port); // Open a socket at port 1565
            fromServer = new BufferedReader(new InputStreamReader(sock.getInputStream())); //Buffer to append response from server

            // Read response from server
            textFromServer = fromServer.readLine();
            if (textFromServer != null)
                System.out.println((secondary == (-1) ? "<S2> " : "") + textFromServer + "\n");// Formulate response if its coming from secondary server
            sock.close();
        } catch (IOException x) {
            System.out.println("Socket error.");
            x.printStackTrace();
        }
    }
}