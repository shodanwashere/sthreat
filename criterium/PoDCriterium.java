package criterium;

import org.AnPacket;

/**
 * Criterium for analysing packets, with a focus on PoD (Ping of Death)
 * attacks.
 * 
 * @author nunoDias fc56330
 */
public class PoDCriterium implements Criterium{
    private String critName = "Ping of Death";

    public String getCritName(){
        return critName;
    }

    public boolean apply(AnPacket packet){
        boolean result = false;
        if(!packet.getICMP().equals("")){
            if(packet.getICMP().equals("8") && (packet.getPacketLength() > 84))
                result = true;
        }
        return result;
    }
}
