/* 
 * Name: Carlos Guzman
 * Date: 10/30/2022
 * 
 * Java Version: 18.0.2.1
 * 
 * Compilation: javac -cp "gson-2.8.2.jar" Blockchain.java
 * 
 * Instructions: first parameter [process pid]
 * Examples: 
 *      >java ".:gson-2.8.2.jar" Blockchain 0
 *      >java ".:gson-2.8.2.jar" Blockchain 1
 *      >java ".:gson-2.8.2.jar" Blockchain 2
 *
 * 
 * Comments:
 *      Used code from the supplied files. Gave credit in comments for code I used from the internet. 
 *      Create a random seed:
 *          (https://www.baeldung.com/java-random-string)
 *      Create a custom date:
 *          (https://stackoverflow.com/questions/22326339/how-create-date-object-with-values-in-java)
 *      Create a custom UUID:
 *          (https://stackoverflow.com/questions/20840256/create-uuid-with-zeros)
 * 
 *      Reading lines and tokens from a file:
 *          http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
 *      Good explanation of linked lists:
 *          https://beginnersbook.com/2013/12/linkedlist-in-java-with-example/
 *      Priority queue:
 *          https://www.javacodegeeks.com/2013/07/java-priority-queue-priorityqueue-example.html
 *          
 *    The web sources:
 *
 *      https://mkyong.com/java/how-to-parse-json-with-gson/
 *        http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
 *        https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
 *        https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
 *        https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
 *        https://www.mkyong.com/java/java-sha-hashing-example/
 *        https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
 *        https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
 *
 *        One version of the JSON jar file here:
 *        https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.2/    
 *        
 *        https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  @author JJ
 *        https://dzone.com/articles/generate-random-alpha-numeric  by Kunal Bhatia  ·  Aug. 09, 12 · Java Zone  
 */
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.io.Serializable;
import java.io.StringWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Comparator;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

class PublicKeyMap {
    /*
     * HashMap to hold the public keys of all the processes. 
     * Static so it can be used throughout the program.
     */
    private static HashMap<Integer, PublicKey> publicKeyMap = new HashMap<Integer, PublicKey>();
    public static void put(Integer PID, PublicKey key) {
        publicKeyMap.put(PID, key);
    }

    public static boolean containsPID(Integer pid) {
        return publicKeyMap.containsKey(pid);
    }
    public static HashMap<Integer, PublicKey> get() {
        return publicKeyMap;
    }
    public static int size() {
        return publicKeyMap.size();
    }
}

class BlockRecord implements Serializable{
    /*
     * BlockRecord class using the same concept from the supplied files
     */
    // Block Header Fields
    String BlockNumber = "";
    String BlockID = "";
    String CreatorID = "";
    String SignedBlockID = "";
    String VerificationProcessID = "";
    String RandomSeed = "";
    String PoWHash = "";
    String SignedPoWHash = "";
    String TimeStamp = "";
    String DataHash = "";

    // Payload Data Fields//
    String Fname = "";
    String Lname = "";
    String DOB = "";
    String SSN = "";
    String Diagnosis = "";
    String Treatment = "";
    String Rx = "";
  
    public String getBlockID() {return BlockID;}
    public void setBlockID(String id){this.BlockID = id;}

    public String getCreatorID() {return CreatorID;}
    public void setCreatorID(String id) {this.CreatorID = id;}

    public String getSignedBlockID() {return SignedBlockID;}
    public void setSignedBlockID(String sign) {this.SignedBlockID = sign;}

    public String getVerificationProcessID() {return VerificationProcessID;}
    public void setVerificationProcessID(String id){this.VerificationProcessID = id;}

    public String getRandomSeed() {return RandomSeed;}
    public void setRandomSeed(String seed) {this.RandomSeed = seed;}

    public String getPoWHash() {return PoWHash;}
    public void setPoWHash(String hash) {this.PoWHash = hash;}

    public String getSignedPoWHash() {return SignedPoWHash;}
    public void setSignedPoWHash(String hash) {this.SignedPoWHash = hash;}

    public String getTimeStamp() {return TimeStamp;}
    public void setTimeStamp(String date) {this.TimeStamp = date;}

    public String getDataHash() {return DataHash;}
    public void setDataHash(String hash) {this.DataHash = hash;}

    public String getBlockNumber() {return BlockNumber;}
    public void setBlockNumber(String n) {this.BlockNumber = n;}
  
    public String getFname() {return Fname;}
    public void setFname (String fname){this.Fname = fname;}

    public String getLname() {return Lname;}
    public void setLname (String lname){this.Lname = lname;}

    public String getDOB() {return DOB;}
    public void setDOB (String dob){this.DOB = dob;}
    
    public String getSSN() {return SSN;}
    public void setSSN (String ssn){this.SSN = ssn;}
  
    public String getDiagnosis() {return Diagnosis;}
    public void setDiagnosis (String diagnosis){this.Diagnosis = diagnosis;}
  
    public String getTreatment() {return Treatment;}
    public void setTreatment (String treatment){this.Treatment = treatment;}
  
    public String getRx() {return Rx;}
    public void setRx (String rx){this.Rx = rx;}

    public String toJson() {
        // Used to print the block to the console.
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(this, BlockRecord.class);
        return json;
    }
    
}

class PublicKeyServer implements Runnable {
    /*
     *  Server to accept Public Keys sent from a process.
     *  Stores the keys in the PublicKeyMap.
     */
    private int port; // port to use
    private boolean keyFromTwo = false; // Used to start the initiation of the blockchain. Start when we receive the keys from 2
    
    PublicKeyServer(Integer pid) {
        port = 4710 + pid; // Port to accept public keys
        // Initialize the hash map and add the current process' PID and PublicKey
        PublicKeyMap.put(pid, Blockchain.keyPair.getPublic());
    }
    public void run() {
        int q_len = 6; //queue length of incoming data
        Socket sock;
        System.out.println("Starting Public Key Server input thread using port " + port + ".");
        try {
            // Accept a key sent at the port from a process.
            ServerSocket servSock = new ServerSocket(port, q_len);
            while (true) {
                sock = servSock.accept();
                new PublicKeyWorker(sock).start();
            }
        } catch (IOException x){ x.printStackTrace(); }
    }

    public boolean receivedKeyFromTwo() {
        return keyFromTwo; 
    }

    public void sendPublicKeys (int[] PIDs, int pid, PublicKey key){ 
        /*
         *  Multicast our public key to the other processes.
         *  Sending them as a json.
         */
		Socket sock;
		ObjectOutputStream toServer;
		try{
            // Create a json object of the the key.
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            byte[] byteKey = key.getEncoded(); //Encode the key as a byte array.
            String stringKey = Base64.getEncoder().encodeToString(byteKey); //turn the byte array to a string
            String json = gson.toJson(new PublicKeyJSON(pid, stringKey), PublicKeyJSON.class); //Create json object of the key. Created a custom task to keep it in json form.
            System.out.println("Sending Process " + pid + " and  Public Key " + stringKey + ".");
			for(int i=0; i< PIDs.length; i++) {
                // Send our public key to all servers.
				sock = new Socket("localhost", 4710+PIDs[i]);
				toServer = new ObjectOutputStream(sock.getOutputStream());
                toServer.writeObject(json);
				toServer.flush();
				sock.close();
			}
		}catch (Exception x) {x.printStackTrace ();}
    }

    class PublicKeyJSON {
        /*
         * This class is used to send the public key and the process it came from to other processes
         * We need this to send them as a json object and keep everything together.
         */
        private int PID;
        private String key;
        PublicKeyJSON(int p, String k) { PID = p; key = k; }
        public int getPID() { return PID; }
        public String getKey() { return key; }
    }

    class PublicKeyWorker extends Thread {
        /*
         * Worker Thread to retrieve the public keys.
         */
        Socket sock;
        PublicKeyWorker(Socket s) { sock = s; } 
        public void run() {
            Gson gson = new Gson(); // Use the gson library to store the retrieved json object
            try {
                // Retrieve the PublicKeyJSON object from the processes sending it.
                ObjectInputStream in = new ObjectInputStream(sock.getInputStream()); 
                PublicKeyJSON json = gson.fromJson((String) in.readObject(), PublicKeyJSON.class); // convert the string to a PublicKeyJSON object
                int pid = json.getPID(); // Retrieve the pid
                String stringKey = json.getKey(); // Retrieve the PublicKey in string form.
                System.out.println("Received from Process " + pid + " and Public Key " + stringKey + ".");

                // Restore Public Key Object from the String
                byte[] byteKey = Base64.getDecoder().decode(stringKey);
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(byteKey);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey key = keyFactory.generatePublic(pubSpec);

                // Add the public key if its not in the Hash Map.
                if (!PublicKeyMap.containsPID(pid)) {
                    PublicKeyMap.put(pid, key);
                    if (pid == 2)
                        keyFromTwo = true; // Received the key from process 2.
                }
            } catch (Exception x){x.printStackTrace();}
        }
    }
    
}

class UnverifiedBlockProducer {
    /*
     * This class is used to read the information from the input files.
     */
    private int pid;
    private LinkedList<BlockRecord> blockList;

    private final int FNAME = 0;
    private final int LNAME = 1;
    private final int DOB = 2;
    private final int SSN = 3;
    private final int DIAGNOSIS = 4;
    private final int TREATMENT = 5;
    private final int RX = 6;

    UnverifiedBlockProducer(int p) {
        pid = p;
        blockList = new LinkedList<BlockRecord>();
        readRecordsFiles(); 
    }
    public LinkedList<BlockRecord> getLocalBlockList() { return blockList; }

    public void run() { 
        // Wait until we have all the public keys.
        while (PublicKeyMap.size() != 3)
            System.out.print("\r");
        sendRecords(PublicKeyMap.get().keySet());
    }
    private void readRecordsFiles() {
        /*
         * Used to read the input files and create blocks from the data.
         */
        String FILENAME;
        // Use the correct input file
        switch (pid) {
            case 1:
                FILENAME = "BlockInput1.txt";
                break;
            case 2:
                FILENAME = "BlockInput2.txt";
                break;
            default:
                FILENAME = "BlockInput0.txt";
                break;
        }

        try {
            System.out.println("Using input file: " + FILENAME);
            BufferedReader br = new BufferedReader(new FileReader(FILENAME));
            String[] tokens = new String[10];
            String line;
      
            int n = 0;
            
            // Begin reading the data from the file line by line
            while ((line = br.readLine()) != null) {
	
                BlockRecord block = new BlockRecord(); // Get ready to store data
        
                try{Thread.sleep(1001);}catch(InterruptedException e){} // Sleep for randomness

                // Create the time stamp.
                Date date = new Date(); 
                String TimeStamp = String.format("%1$s %2$tF.%2$tT", "", date) + "." + pid;

                // Set Block Data first //
                block.setBlockID(new String(UUID.randomUUID().toString()));

                // Sign the Block ID
                byte[] signedBlockID = Blockchain.signData(block.getBlockID().getBytes("UTF-8"), Blockchain.keyPair.getPrivate());
                block.setSignedBlockID(Base64.getEncoder().encodeToString(signedBlockID));

                // Set the rest of the header data
                block.setCreatorID(Integer.toString(pid));
                block.setVerificationProcessID("");
                block.setTimeStamp(TimeStamp);
        
                // Set Payload Data //
                tokens = line.split(" +");
                block.setFname(tokens[FNAME]);
                block.setLname(tokens[LNAME]);
                block.setDOB(tokens[DOB]);
                block.setSSN(tokens[SSN]);
                block.setDiagnosis(tokens[DIAGNOSIS]);
                block.setTreatment(tokens[TREATMENT]);
                block.setRx(tokens[RX]);
 
                // Create Block Payload to hash//
                StringBuilder payload = new StringBuilder();
                payload.append(block.getFname());
                payload.append(block.getLname());
                payload.append(block.getDOB());
                payload.append(block.getSSN());
                payload.append(block.getDiagnosis());
                payload.append(block.getTreatment());
                payload.append(block.getRx());

                // Hash with SHA-256 algorithm
                byte[] SignedDataHashBytes = Blockchain.signData(payload.toString().getBytes("UTF-8"), Blockchain.keyPair.getPrivate());

                // Set the Data Hash in the block
                block.setDataHash(Base64.getEncoder().encodeToString(SignedDataHashBytes));

                // Add block to list of created blocks
                blockList.add(block);
                n++;
            }
            br.close();
            System.out.println(n + " records read." + "\n");
        } catch (Exception e) { e.printStackTrace(); }
    }
    private void sendRecords(Set<Integer> PIDs) {
        /*
         * Used to send the records retrieved from the input files to the other processes
         */
        Socket sock;
        ObjectOutputStream toServer;
        Random r = new Random();
        try {
            // Send to each process
            for (Integer pid : PIDs) {
                System.out.println("Sending Blocks to process " + pid + "...");

                // Send each block one by one.
                for (BlockRecord blockRecord : blockList){
                    sock = new Socket("localhost", 4820 + pid);
                    toServer = new ObjectOutputStream(sock.getOutputStream());
                    Thread.sleep((r.nextInt(9) * 100)); 
                    toServer.writeObject(blockRecord.toJson());
                    toServer.flush();
                    sock.close();
                } 
            }
            System.out.println("Done Sending Blocks");
        Thread.sleep((r.nextInt(9) * 100)); 
		}catch (Exception x) { x.printStackTrace (); }
    }

}

class UnverifiedBlockServer implements Runnable {
    /*
     * This Server just accepts any new unverified blocks sent
     * to this process at the given port.
     */
    PriorityBlockingQueue<BlockRecord> queue;
    private int port;

    UnverifiedBlockServer(PriorityBlockingQueue<BlockRecord> queue, int p){
		this.queue = queue;
        port = 4820 + p;
    }

    class UnverifiedBlockServerWorker extends Thread {
        /*
         * Worker class to retrieve the block and covert it from a json object
         * to a BlockRecord object.
         */
		Socket sock;
		UnverifiedBlockServerWorker (Socket s) {sock = s;}
		BlockRecord block = new BlockRecord();
		
		public void run(){
            try{
                Gson gson = new Gson();
                ObjectInputStream in = new ObjectInputStream(sock.getInputStream());

                // Covert from json object to a BlockRecord object.
                block = gson.fromJson((String) in.readObject(), BlockRecord.class); 
                queue.put(block); // Add to the priority blocking queue
                sock.close(); 
            } catch (Exception x){x.printStackTrace();}
		}
    }

    public void run() {
        /*
         * Start the server at port 4820 + pid
         * Accept any new unverified blocks coming in.
         */
        int q_len = 6;
        Socket sock;
        System.out.println("Starting the Unverified Block Server input thread using " + port);
        try{
          ServerSocket servSock = new ServerSocket(port, q_len);
          while (true) {
            sock = servSock.accept(); // Got a new unverified block
            new UnverifiedBlockServerWorker(sock).start(); // So start a thread to process it.
          }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
    
}

class UnverifiedBlockConsumer implements Runnable {
    /*
     * This class starts processing the unverfied blocks
     * and hopes to solve the puzzle before the other nodes
     * in the blockchain. Then it sends the verified block to the other
     * nodes in the blockchain.
     * 
     * Also creates the genesis block of the blockchain.
     */
    PriorityBlockingQueue<BlockRecord> queue; //Unverified Blocks in queue
    LinkedBlockingQueue<BlockRecord> ledger; // The current blockchain ledger
    private int pid;
    UnverifiedBlockConsumer(PriorityBlockingQueue<BlockRecord> q, LinkedBlockingQueue<BlockRecord> l, int p) {
        queue = q;
        ledger = l;
        pid = p;
        if (pid == 2) {
            // Have processes 2 create the genesis block
            createGenesis(pid);
        }
        try {Thread.sleep(5000);} catch (InterruptedException e) {e.printStackTrace();} // Sleep to allow genesis block sent
    }


    public void run() {
        try {
            while (!queue.isEmpty()) { // Continue until all the unverified nodes are done.
                System.out.println(queue.size() + " Nodes Left to validate.");
                boolean puzzleSolved = false; // Is the puzzle solved
                final int WORK_THRESH = 2000; // Threshold to compare the hash. Real work.
                final long SLEEP_TIME = 3000; // Sleep time for fake work.
                BlockRecord unverifiedBlock = queue.take(); //deque the head of the queue.
                while (!puzzleSolved) { // Continue until the puzzle is solved
                    
                    boolean blockInChain = false; // Is the block already in the chain?
                    System.out.println("Ledger size: " + ledger.size());

                    // Check if the unverified block has been verified by someone else.
                    for (BlockRecord verifiedBlock : ledger) {
                        if (unverifiedBlock.getBlockID().equals(verifiedBlock.getBlockID())) {
                            // Block is already in the blockchain.
                            System.out.println("Block: " + unverifiedBlock.getBlockID() + " in blockchain.");
                            blockInChain = true;
                            puzzleSolved = true;
                            break;
                        }
                    }

                    if (!blockInChain) {
                        // Block not in the blockchain time to solve the puzzle
                        // But first Verify the signed BlockID
                        int creatorID = Integer.parseInt(unverifiedBlock.getCreatorID());
                        byte[] blockID = unverifiedBlock.getBlockID().getBytes("UTF-8");
                        byte[] signature = Base64.getDecoder().decode(unverifiedBlock.getSignedBlockID());

                        if (Blockchain.verifySig(blockID, PublicKeyMap.get().get(creatorID), signature)) {
                            // Verified the BlockID
                            System.out.println("Block " + unverifiedBlock.getBlockID() + "\'s ID verified.");
                        }
                        else {
                            // Could not verify it.
                            System.out.println("BlockID " + unverifiedBlock.getBlockID() + "\'s ID could not be verified.");
                            System.out.println("Discarding Block");
                            break;
                        }

                        // Verify the signed Data Hash
                        byte[] signedDataHash = Base64.getDecoder().decode(unverifiedBlock.getDataHash());

                        // Create Block Payload to hash//
                        StringBuilder payload = new StringBuilder();
                        payload.append(unverifiedBlock.getFname());
                        payload.append(unverifiedBlock.getLname());
                        payload.append(unverifiedBlock.getDOB());
                        payload.append(unverifiedBlock.getSSN());
                        payload.append(unverifiedBlock.getDiagnosis());
                        payload.append(unverifiedBlock.getTreatment());
                        payload.append(unverifiedBlock.getRx());

                        // Side quest: verify the payload Data Hash
                        byte[] payloadBytes = payload.toString().getBytes("UTF-8");
                        
                        if (Blockchain.verifySig(payloadBytes, PublicKeyMap.get().get(creatorID), signedDataHash)) {
                            // Data Hash verified
                            System.out.println("Block " + unverifiedBlock.getBlockID() + "\'s DataHash verified.");
                        }
                        else {
                            // Could not verify it. Possible secret key leak.
                            System.out.println("BlockID " + unverifiedBlock.getBlockID() + "\'s DataHash could not be verified.");
                            System.out.println("Discarding Block");
                            break;
                        }

                        // Create random value (Credit: https://www.baeldung.com/java-random-string)
                        byte[] array = new byte[3]; // length is bounded by 7
                        new Random().nextBytes(array);
                        String randomSeed = new String(array, Charset.forName("UTF-8"));

                        // Get the previous block number and winning hash from previous block in the chain
                        int blockNumber = 0;
                        String previousPoWHash = "";
                        for (BlockRecord verifiedBlock : ledger) {
                            blockNumber = Integer.parseInt(verifiedBlock.getBlockNumber());
                            previousPoWHash = verifiedBlock.getPoWHash();
                        }
                        
                        // Set the potential block number in the chain.
                        unverifiedBlock.setBlockNumber(Integer.toString(blockNumber+1));

                        //Set Verification ID
                        unverifiedBlock.setVerificationProcessID(Integer.toString(pid));
                        
                        //Add the current Block's block number and VerificationID to the payload
                        payload.append(unverifiedBlock.getVerificationProcessID());
                        payload.append(unverifiedBlock.getBlockNumber());

                        // Hash the concatenated (PreviousPoWHash + Payload + RandomSeed) with SHA-256 algorithm
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        md.update ((previousPoWHash+payload.toString()+randomSeed).getBytes("UTF-8"));
                        byte[] workHashBytes = md.digest();
                        String workHashStr = Blockchain.ByteArrayToString(workHashBytes);
                        

                        // Check if we solved the puzzle
                        int workNumber = Integer.parseInt(workHashStr.substring(0,4),16); // Between 0000 (0) and FFFF (65535)
                        System.out.println("First 16 bits in Hex and Decimal: " + workHashStr.substring(0,4) +" and " + workNumber);

                        if (workNumber < WORK_THRESH) {
                            // Puzzle solved!
                            System.out.println("Puzzle Solved for block " + unverifiedBlock.getBlockID() + "!");
                            System.out.println("Seed is " + randomSeed + ".");
                            
                            // Sign the winning PoW Hash
                            byte[] signedPoWHash = Blockchain.signData(workHashBytes, Blockchain.keyPair.getPrivate());

                            // Set the winning parameters
                            unverifiedBlock.setSignedPoWHash(Base64.getEncoder().encodeToString(signedPoWHash));
                            unverifiedBlock.setPoWHash(workHashStr);
                            unverifiedBlock.setRandomSeed(randomSeed);
                            puzzleSolved = true; // Puzzle solved!
                            
                            // send the verified block to other nodes to add to their blockchain ledger
                            sendBlock(unverifiedBlock, PublicKeyMap.get().keySet()); 
                        }
                        else {
                            // Did Not Win so reset block number and verification ID
                            unverifiedBlock.setBlockNumber("");
                            unverifiedBlock.setVerificationProcessID("");
                        }
                        Thread.sleep(SLEEP_TIME);
                    }
                }
            }
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void createGenesis(int pid) {
        /*
         * This function just creates the genesis block of the blockchain.
         */
        BlockRecord genesis = new BlockRecord(); 
        try {
            try{Thread.sleep(1001);}catch(InterruptedException e){}
            // Create a custom date of the block (My DOB)
            Date date = new GregorianCalendar(1992, Calendar.SEPTEMBER, 15).getTime(); //Credit https://stackoverflow.com/questions/22326339/how-create-date-object-with-values-in-java
            String TimeStamp = String.format("%1$s %2$tF.%2$tT", "", date) + "." + pid;

            // Set Block Data first //

            // Custom UUID of all zeros
            genesis.setBlockID(new String((new UUID(0,0)).toString())); // Credit https://stackoverflow.com/questions/20840256/create-uuid-with-zeros

            // Sign the block id
            byte[] signedBlockID = Blockchain.signData(genesis.getBlockID().getBytes("UTF-8"), Blockchain.keyPair.getPrivate());
            genesis.setSignedBlockID(Base64.getEncoder().encodeToString(signedBlockID));

            // Set the rest of the header data
            genesis.setCreatorID(Integer.toString(pid));
            genesis.setVerificationProcessID("");
            genesis.setTimeStamp(TimeStamp);
    
            // Set Payload Data //
            genesis.setFname("Carlos");
            genesis.setLname("Guzman");
            genesis.setDOB("1992.09.05");
            genesis.setSSN("000-00-0000");
            genesis.setDiagnosis("Homework Phobia");
            genesis.setTreatment("No more Homework");
            genesis.setRx("No Homework");

            // Create Block Payload to hash//
            StringBuilder payload = new StringBuilder();
            payload.append(genesis.getFname());
            payload.append(genesis.getLname());
            payload.append(genesis.getDOB());
            payload.append(genesis.getSSN());
            payload.append(genesis.getDiagnosis());
            payload.append(genesis.getTreatment());
            payload.append(genesis.getRx());

            // Sign the payload data to hash it
            byte[] SignedDataHashBytes = Blockchain.signData(payload.toString().getBytes("UTF-8"), Blockchain.keyPair.getPrivate());
            String SignedDataHash = Base64.getEncoder().encodeToString(SignedDataHashBytes);
            
            // Set the Data Hash in the block
            genesis.setDataHash(SignedDataHash);


            // Create random value (Credit: https://www.baeldung.com/java-random-string)
            byte[] array = new byte[3]; // length is bounded by 7
            new Random().nextBytes(array);
            String randomSeed = new String(array, Charset.forName("UTF-8"));
            genesis.setRandomSeed(randomSeed);

            // Hash the updated block data
            genesis.setVerificationProcessID(Integer.toString(pid));


            genesis.setBlockNumber("0");
            // System.out.println(genesis.toJson());

            payload.append(genesis.getVerificationProcessID());
            payload.append(genesis.getBlockNumber());

            // Concatenate The SHA-256 hash value of the previous block, data in the current block, & a random string R
            String PoW_String = SignedDataHash + payload + randomSeed;

            // Hash the PoW String
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update (PoW_String.getBytes("UTF-8"));
            byte[] PoWBytes = md.digest();
            String PoWHash = Blockchain.ByteArrayToString(PoWBytes);
            genesis.setPoWHash(PoWHash);

            byte[] signedPoWHash = Blockchain.signData(PoWBytes, Blockchain.keyPair.getPrivate());
            genesis.setSignedPoWHash(Base64.getEncoder().encodeToString(signedPoWHash));

            System.out.println("Genesis Block created by process " + pid + ".");
            sendBlock(genesis, PublicKeyMap.get().keySet());
        } catch (Exception e) { e.printStackTrace(); }
    }

    public void sendBlock(BlockRecord block, Set<Integer> PIDs) {
        /*
         * This function sends a block to the other nodes in the blockchain.
         * Ideally used to send verified nodes only.
         */
        Socket sock;
        ObjectOutputStream toServer;
        try {
            // Send block to other nodes
            for (Integer pid : PIDs) {
                System.out.println("Sending Verified Block to " + pid + "...");
                sock = new Socket("localhost", 4930 + pid);
                toServer = new ObjectOutputStream(sock.getOutputStream());
                toServer.writeObject(block.toJson());
                toServer.flush();
                sock.close();
            }
		}catch (Exception x) { x.printStackTrace (); }
    }
}

class LedgerServer implements Runnable {
    /*
     * This server is used to updat blockchain ledger 
     * It accepts verified nodes and adds them to the ledger.
     */
    private int port;
    private int pid;
    LinkedBlockingQueue<BlockRecord> ledger;
    LedgerServer(LinkedBlockingQueue<BlockRecord> l, int p) {
        pid = p;
        port = 4930 + pid;
        ledger = l;
    }
    class LedgerServerWorker extends Thread {
        /*
         * Worker class to read the verfieid node. Convert from json to BlockRecord.
         * Add the new verified block to the blockchain ledger.
         */
        Socket sock;
        LedgerServerWorker(Socket s) { sock = s; }
		public void run(){
            BlockRecord block;
            try{
                // Retrieve block json object and covert to BlockRecord
                Gson gson = new Gson();
                ObjectInputStream in = new ObjectInputStream(sock.getInputStream());
                block = gson.fromJson((String) in.readObject(), BlockRecord.class); 

                System.out.println("Received Verified Block from Process " + block.getVerificationProcessID() + ".");

                ledger.put(block); // Add to our ledger.
                sock.close(); 
                if (pid == 0)
                    printLedger(); // Node 0 prints the updated ledger every time it updates.
            } catch (Exception x){x.printStackTrace();}
		}
    }
    public void run() {
        /*
         * Accept incoming verified blocks from other processes.
         */
        int q_len = 6;
        Socket sock;
        System.out.println("Starting The Ledger Server input thread using " + port);
        try {
            ServerSocket servSock = new ServerSocket(port, q_len);
            while (true) {
                sock = servSock.accept();
                (new LedgerServerWorker(sock)).start();
            }
        } catch(IOException ioe) {System.out.println(ioe);}
    }

    private void printLedger() {
        /*
         * Prints the current ledger state in as a json string.
         */
        int n = 0;
        for (BlockRecord block : ledger) {
            System.out.println("Block " + n + ": ");
            System.out.println(block.toJson());
            n++;
        }
    }
}


public class Blockchain {
    public static KeyPair keyPair;

    // Comparator to compare the time stamps in each BlockRecord. Used to sort the priority queue.
    public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>()
    {
        public int compare(BlockRecord b1, BlockRecord b2)
        {
            String s1 = b1.getTimeStamp();
            String s2 = b2.getTimeStamp();
            if (s1 == s2) {return 0;}
            if (s1 == null) {return -1;}
            if (s2 == null) {return 1;}
            return s1.compareTo(s2);
        }
    };

    public static void main(String[] args) throws Exception {
        final int pid = Integer.parseInt(args[0]); // retrieve the current process' pid
        keyPair = generateKeyPair(new Random().nextLong()); // generate the public key and private key

        // Unverified Blocks queue
        final PriorityBlockingQueue<BlockRecord> PriorityQueue = new PriorityBlockingQueue<BlockRecord>(100, BlockTSComparator);
        
        // Blockchain Ledger
        final LinkedBlockingQueue<BlockRecord> Ledger = new LinkedBlockingQueue<>();

        // Start the servers
        PublicKeyServer publicKeyServer = new PublicKeyServer(pid);
        UnverifiedBlockServer unverifiedBlockServer = new UnverifiedBlockServer(PriorityQueue, pid);
        LedgerServer ledgerServer = new LedgerServer(Ledger, pid);
        
        new Thread(publicKeyServer).start();
        new Thread(unverifiedBlockServer).start();
        new Thread(ledgerServer).start();

        // Initiate the sending of the public keys
        int[] PIDs = new int[2];
        switch (pid) {
            // Keep track of which pids to send public keys to.
            case 0:
                // Process 0
                PIDs[0] = 1;
                PIDs[1] = 2;
                break;
            case 1:
                // Process 1
                PIDs[0] = 0;
                PIDs[1] = 2;
                break;
            default:
                // Process 2
                PIDs[0] = 0;
                PIDs[1] = 1;
                break;
        }
       
        if (pid == 2) {
            // Begin Multicast of PublicKeys
            System.out.println(PIDs[0] + " " + PIDs[1]);
            publicKeyServer.sendPublicKeys(PIDs, pid, keyPair.getPublic());
        }
        else {
            // Wait until Process 2 sends its public key.
            while (!publicKeyServer.receivedKeyFromTwo())
                System.out.print("\r"); // Code seems to work when I add this to the loop (Even though it does nothing). Maybe I should use sleep()
            
            // Begin sending your public key
            publicKeyServer.sendPublicKeys(PIDs, pid, keyPair.getPublic());
        }
        
        // Begin reading the block records
        UnverifiedBlockProducer unverifiedBlockProducer = new UnverifiedBlockProducer(pid);
        unverifiedBlockProducer.run();

        // Begin trying to solve the puzzles
        UnverifiedBlockConsumer unverifiedBlockConsumer = new UnverifiedBlockConsumer(PriorityQueue, Ledger, pid);
        unverifiedBlockConsumer.run();

        Thread.sleep(2000); // Sleep before we verify the final ledger.

        // Verify the ledger and if its process 0 then create the json file of it.
        verifyLedger(Ledger, unverifiedBlockProducer.getLocalBlockList(), pid);
        if (pid == 0) { createLedgerJson(Ledger); }
    }

    public static KeyPair generateKeyPair(long seed) throws Exception {
        /*
         * This class generates a KeyPair object containing the PublicKey and PrivateKey
         */
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);
        keyGenerator.initialize(1024, rng);
        
        return (keyGenerator.generateKeyPair());
    }

    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        /*
         * This class signs the data with a PrivateKey using the SHA256 algorithm with RSA
         */
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }

    public static String ByteArrayToString(byte[] ba){
        /*
         * Coverts a byte array to a string.
         */
		StringBuilder hex = new StringBuilder(ba.length * 2);
		for(int i=0; i < ba.length; i++){
			hex.append(String.format("%02X", ba[i]));
		}
		return hex.toString();
    }    

    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        /*
         * Verifies the data using the PublicKey of someone.
         */
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initVerify(key);
        signer.update(data);
        
        return (signer.verify(sig));
    }

    public static void verifyLedger(LinkedBlockingQueue<BlockRecord> Ledger, LinkedList<BlockRecord> localBlockList, int pid) {
        /*
         * This function verifies the entire blockchain ledger once it is completed.
         */
        String previousPoWHash = "";
        boolean validLedger = true;
        try{
            System.out.println("Validating Ledger...");
            for (BlockRecord block : Ledger) {
                if (Integer.parseInt(block.BlockNumber) != 0) {
                    // Verifying non-genesis blocks
                    // Concat Previous blocks PoWHash + the current Hash + the winning Random seed

                    // Create Block Payload to hash//
                    StringBuilder payload = new StringBuilder();
                    payload.append(block.getFname());
                    payload.append(block.getLname());
                    payload.append(block.getDOB());
                    payload.append(block.getSSN());
                    payload.append(block.getDiagnosis());
                    payload.append(block.getTreatment());
                    payload.append(block.getRx());
                    payload.append(block.getVerificationProcessID());
                    payload.append(block.getBlockNumber());

                    String randomSeed = block.getRandomSeed();

                    // Hash the concatenated (PreviousPoWHash + Payload + RandomSeed) with SHA-256 algorithm
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    md.update ((previousPoWHash+payload.toString()+randomSeed).getBytes("UTF-8"));
                    byte[] PoWHashBytes = md.digest();
                    String PoWHashStr = Blockchain.ByteArrayToString(PoWHashBytes);

                    int winnerPID = Integer.parseInt(block.getVerificationProcessID());
                    PublicKey winnerKey = PublicKeyMap.get().get(winnerPID);
                    byte[] signedPoWHash = Base64.getDecoder().decode(block.getSignedPoWHash());

                    int creatorPID = Integer.parseInt(block.getCreatorID());
                    PublicKey creatorKey = PublicKeyMap.get().get(creatorPID);
                    byte[] signedBlockID = Base64.getDecoder().decode(block.getSignedBlockID());

                    // Check verification of puzzle, signed winning hash, and signed blockID
                    if (!PoWHashStr.equals(block.getPoWHash()) 
                    && !verifySig(PoWHashBytes, winnerKey, signedPoWHash) 
                    && !verifySig(block.getBlockID().getBytes("UTF-8"), creatorKey, signedBlockID)) {
                        // Block could not be verified
                        System.out.println("ERROR: Block " + block.getBlockID() + " could not be verified.");
                        validLedger = false;
                    }

                    // Verity Data Hash
                    if (pid == Integer.parseInt(block.getCreatorID())) {
                        for (BlockRecord localBlock : localBlockList) {
                            if (localBlock.getBlockID().equals(block.getBlockID())) {
                                System.out.println("Verifying Data Hash of Block " + block.getBlockID() + " with the local archived records.");
                                // Create Block Payload to hash//
                                StringBuilder localPayload = new StringBuilder();
                                localPayload.append(localBlock.getFname());
                                localPayload.append(localBlock.getLname());
                                localPayload.append(localBlock.getDOB());
                                localPayload.append(localBlock.getSSN());
                                localPayload.append(localBlock.getDiagnosis());
                                localPayload.append(localBlock.getTreatment());
                                localPayload.append(localBlock.getRx());
                                byte[] localPayloadBytes = localPayload.toString().getBytes("UTF-8");

                                // Sign the local blocks payload to create a hash
                                PrivateKey key = keyPair.getPrivate();
                                String localDataHash = Base64.getEncoder().encodeToString(signData(localPayloadBytes, key));
                                String DataHash = block.getDataHash();

                                if (DataHash.equals(localDataHash)) {
                                    System.out.println("Data Hash Verified with local archive records!");
                                }
                                else {
                                    System.out.println("WARNING!: Data Hash could not be verified!\nPerhaps a secret key leak!");
                                }
                                break;
                            }
                        }
                    }
                }
                previousPoWHash = block.getPoWHash(); // Save the hash of the previous block to use for the next block.
            }
            System.out.println(validLedger ? "Ledger Valid!" : "Ledger Not Valid!");
        } catch (Exception e) { e.printStackTrace(); }
    }

    public static void createLedgerJson(LinkedBlockingQueue<BlockRecord> Ledger) {
        /*
         * This function creates a JSON file of the final blockchain ledger.
         */
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
                
        // Write the JSON object to a file:
        try (FileWriter writer = new FileWriter("BlockchainLedgerSample.json")) {
            gson.toJson(Ledger, writer);
        } catch (IOException e) {e.printStackTrace();}
    }
}
