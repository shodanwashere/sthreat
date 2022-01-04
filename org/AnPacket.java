package org;
import strafan.CompClass;

/**
 * Little class to improve organization and write a more modular packet
 * analysis system.
 */
public class AnPacket{
    private int number;
    private double time;
    private String srcIP;
    private String dstIP;
    private int srcPort;
    private int dstPort;
    private String protocol;
    private String icmpType;
    private int length;
    private String flags;

    public AnPacket(String line){
        String[] splittedLine = CompClass.splitter(line);
	    this.number = Integer.parseInt(splittedLine[0]);
	    this.time = Double.parseDouble(splittedLine[1]);
	    this.srcIP = new String(splittedLine[2]);
	    this.dstIP = new String(splittedLine[3]);
	    if(!splittedLine[4].equals(""))
	        this.srcPort = Integer.parseInt(splittedLine[4]);
	    else
	        this.srcPort = -1;
	    if(!splittedLine[5].equals(""))
	        this.dstPort = Integer.parseInt(splittedLine[5]);
	    else
	        this.dstPort = -1;
	    this.protocol = new String(splittedLine[6]);
	    this.icmpType = new String(splittedLine[7]);
	    this.length = Integer.parseInt(splittedLine[8]);
	    this.flags = new String(splittedLine[9]);
    }

    public int getPacketNumber(){
        return this.number;
    }

    public double getPacketTime(){
        return this.time;
    }

    public String getSourceIP(){
        return new String(this.srcIP);
    }

    public String getDestIP(){
        return new String(this.dstIP);
    }

    public int getSourcePort(){
        return this.srcPort;
    }

    public int getDestPort(){
        return this.dstPort;
    }

    public String getProtocol(){
        return new String(this.protocol);
    }

    public String getICMP(){
        return new String(this.icmpType);
    }

    public int getPacketLength(){
        return this.length;
    }

    public String getFlagSeq(){
        return new String(this.flags);
    }
}
