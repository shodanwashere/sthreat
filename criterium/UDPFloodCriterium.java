package criterium;
import org.AnPacket;

/**
 * Criterium for analysing packets, with a focus on UDP Flood
 * attacks.
 * 
 * @author nunoDias fc56330
 */
public class UDPFloodCriterium implements Criterium{
    private String critName = "UDP Flood";

    public String getCritName(){
        return critName;
    }

    public boolean apply(AnPacket packet){
        boolean result = true;
        try{
            if(!packet.getProtocol().equals("DNS") || packet.getPacketLength() <= 512)
                result = false;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
        }
        return result;
    }
}
