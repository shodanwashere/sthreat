package criterium;

import org.AnPacket;
import strafan.CompClass;

/**
 * Criterium for analysing packets, with a focus on SYN Flood
 * attacks.
 * 
 * @author nunoDias fc56330
 */
public class SYNFloodCriterium implements Criterium{
    private String critname = "SYN Flood";

    public String getCritName(){
        return critname;
    }

    public boolean apply(AnPacket packet){
        boolean result = true;
        try{
            if(packet.getProtocol().equals("TCP")){
                if(!(packet.getFlagSeq().equals(CompClass.binSeqToHex("000010")) || packet.getFlagSeq().equals(CompClass.binSeqToHex("000110")))){
                    result = false;
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
        return result;
    }
}
