import strafan.*;
import java.io.*;
import java.util.*;
import org.AnPacket;
import criterium.*;

/**
 * sthreat, short for "Shodan's Threat Analyzer", is a program written as an auxiliator for a mini-project for the
 * Computer Networking Curricular Unit of the school year of 2021/2022, Bachelor's in Computer Engineering at the
 * Faculty of Sciences of the University of Lisbon (Faculdade de Ciências da Universidade de Lisboa).
 * 
 * It makes extensive use of another program I wrote, strafan ("Shodan's Traffic Analyzer"), to pull data from CSV
 * files containing network traffic data for further analysis.
 * 
 * @author nunoDias fc56330
 */
public class sthreat{
    /**
     * To be ignored: shows the SThreat logo on startup
     */
    public static void mainTitle(){
        System.out.println("Thank you for using");
	    System.out.println(" ________  _________  ___  ___  ________  _______   ________  _________");
	    System.out.println("|\\   ____\\|\\___   ___\\\\  \\|\\  \\|\\   __  \\|\\  ___ \\ |\\   __  \\|\\___   ___\\");
	    System.out.println("\\ \\  \\___|\\|___ \\  \\_\\ \\  \\\\\\  \\ \\  \\|\\  \\ \\   __/|\\ \\  \\|\\  \\|___ \\  \\_|");
        System.out.println(" \\ \\_____  \\   \\ \\  \\ \\ \\   __  \\ \\   _  _\\ \\  \\_|/_\\ \\   __  \\   \\ \\  \\");
        System.out.println("  \\|____|\\  \\   \\ \\  \\ \\ \\  \\ \\  \\ \\  \\\\  \\\\ \\  \\_|\\ \\ \\  \\ \\  \\   \\ \\  \\");
        System.out.println("    ____\\_\\  \\   \\ \\__\\ \\ \\__\\ \\__\\ \\__\\\\ _\\\\ \\_______\\ \\__\\ \\__\\   \\ \\__\\");
        System.out.println("   |\\_________\\   \\|__|  \\|__|\\|__|\\|__|\\|__|\\|_______|\\|__|\\|__|    \\|__|");
        System.out.println("   \\|_________|");
	    System.out.println(""); // empty line
    }

    /**
     * Receives an input corresponding to a CSV files and pulls all of its packet data into a list
     * @param input BufferedReader pointing to a properly formatted CSV file
     * @return List of packets
     */
    public static List<AnPacket> listOfPackets(BufferedReader input){
        String line;
	boolean first = true;
	    List<AnPacket> ls = new LinkedList<AnPacket>();
	    try {
	        while((line = input.readLine()) != null){
		    if(first) { first = false; continue; }
	            System.out.print("Got " + ls.size() + " packets\r");
	            ls.add(new AnPacket(line));
	        }
	    } catch (Exception e) {
	        System.err.println("Error: " + e.getMessage());
	    }
	    System.out.println("Got " + ls.size() + " packets :: Finished!");
	    return ls;
    }

    /**
     * Main menu that will loop until the "exit" option is chosen
     * @param packetLs List of packets to be passed to one of the main functions
     * @return Value to let the main program know wether to stop execution or not
     */
    public static boolean mainMenu(List<AnPacket> packetLs) throws Exception{
        System.out.println("Choose your option:");
        System.out.println("--------------------------------");
        System.out.println("(1) SYN Flood Detection");
        System.out.println("(2) UDP Flood Detection");
        System.out.println("(3) PoD Detection");
        System.out.println("(0) Exit");
        Scanner sc = new Scanner(System.in);
        System.out.print("Option $ ");
        int option = sc.nextInt();
        double timeInterval = 0;
        if(option != 0){
            System.out.print("Choose a time interval (seconds) $ ");
            timeInterval = sc.nextDouble();
        }
        boolean exit = false;
        Criterium crit = null;
        switch(option){
            case 1 : crit = new SYNFloodCriterium(); break;
            case 2 : crit = new UDPFloodCriterium(); break;
            case 3 : crit = new PoDCriterium(); break;
            case 0 : exit = true;
        }
        if(crit != null){
            List<Integer> freqs = estabilishFrequency(packetLs, crit, timeInterval);
            System.out.println(freqs.size() + " frequencies obtained!");
            int sum = 0;
            for(int freq: freqs){
                sum += freq;
            }
            double avg = ((double) sum) / ((double) freqs.size());
            System.out.printf("Avg rate: %.2f Packets/Sec\n", avg);
            dataPrintingRoutine(freqs, timeInterval);
        }
        return exit;
    }

    /**
     * Takes a list of packets and a criterium by which to generate a list of frequencies (which should
     * be interpreted as "x packets/time_interval").
     * @param packetLs - List of packets to evaluate
     * @param crit     - Criterium to use for evaluation
     * @return         - List of frequencies in each time interval
     */
    public static List<Integer> estabilishFrequency(List<AnPacket> packetLs, Criterium crit, double interval){
        System.out.print("\033[H\033[2J");
        System.out.flush();
        System.out.println("Initiating " + crit.getCritName() + " detection.");
        List<Integer> freqList = new LinkedList<Integer>();

        Deque<AnPacket> packetTrain = new LinkedList<AnPacket>();

        final double TIME_INTERVAL = interval;
        final double diff = TIME_INTERVAL / 2.00;
        LoadingBar lb = new LoadingBar(packetLs.size());

        for(AnPacket packet: packetLs){
            packetTrain.addFirst(packet);
            lb.update_curr_status(packet.getPacketNumber());
            double timeInt = packetTrain.peekFirst().getPacketTime() - packetTrain.peekLast().getPacketTime();
            lb.show_loading_bar();
            if(packetTrain.size() > 1){
                if(timeInt > TIME_INTERVAL){
                    int freq = 0;
                    for(AnPacket passenger: packetTrain){
                        if(crit.apply(passenger))
                            freq++;
                    }
                    freqList.add(freq);
                    packetTrain.clear();
                }
            }
        }
        System.out.println("");

        return freqList;
    }

    /**
     * Dataset Printing Routine - Takes the list of registered frequencies and the interval used
     * and prints out a dataset file and a complementary myPlot.gp file to render the gnuplot of
     * packet transmission rates of the supplied criterium
     * @param freqList - List of registered frequencies
     * @param interval - Time interval used as a metric
     * @throws Exception - ignore
     */
    public static void dataPrintingRoutine(List<Integer> freqList, double interval) throws Exception{
        System.out.print("Please specify the filename to print frequency dataset (default: myData.txt): ");
        Scanner sc1 = new Scanner(System.in);
        String filename = sc1.nextLine();
        if(filename.equals(""))
            filename = new String("myData.txt");
        int maxFrequency = 0;

        File dataSet = new File(filename);
        BufferedWriter bw = new BufferedWriter(new FileWriter(dataSet));

        LoadingBar lb = new LoadingBar(freqList.size());
        int counter = 0;
        double time = 0.00;
        System.out.println("Printing data set to \""+ filename +"\"...");
        for(Integer freq : freqList){
            System.out.print("Max Frequency: " + maxFrequency +" ");
            lb.show_loading_bar();
            if(freq > maxFrequency)
                maxFrequency = freq;
            bw.write(time + " " + freq +"\n");
            counter++;
            lb.update_curr_status(counter);
            time += interval;
        }
        bw.close();
        System.out.println("\nDone!");
        BufferedWriter myGnuplotFile = new BufferedWriter(new FileWriter("myPlot.gp"));
        	myGnuplotFile.write("set terminal svg size 1280,720\n");
		    myGnuplotFile.write("set output 'plot.svg'\n");
    		myGnuplotFile.write("set xrange [0.00:"+time+"]\n");
    		myGnuplotFile.write("set yrange [0:"+ (maxFrequency + 50) +"]\n");
    		myGnuplotFile.write("plot '"+filename+"' with lines\n");

    		// myDataFile.close();
    		myGnuplotFile.close();
        System.out.println("You can render your data into a graph with the command $ gnuplot myPlot.gp");
    }

    public static void main(String argv[]) throws Exception{
        System.out.print("\033[H\033[2J");
        System.out.flush();
        mainTitle();

        if(argv.length < 1){
            System.err.println("Error: you have not inserted a filename");
	        System.out.println("Usage: java sthreatan <filename>");
	        System.exit(1);
        }

        if(!CompClass.checkFile(argv[0])){
            System.err.println("Error: file does not exist or is directory");
	        System.exit(2);
        }

        File file = new File(argv[0]);
        FileReader fr = new FileReader(file);
        BufferedReader br = new BufferedReader(fr);
        System.out.println("Please wait. We are now copying the file data into RAM.");
        List<AnPacket> packetList = listOfPackets(br);
        br.close();
        fr.close();

        boolean exit;
        do{
            exit = mainMenu(packetList);
        } while(!exit);

        System.out.println("Exiting SThreat");
        packetList.clear();
    }
}
