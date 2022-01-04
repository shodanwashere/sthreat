package criterium;
import org.AnPacket;
/**
 * Lol look at shodan trying to use interfaces to improvise class inheritance again
 * what an idiot amirite
 * 
 * Interface used to write a modular packet analysis system
 * 
 * @author nunoDias fc56330
 */
public interface Criterium {
    public String getCritName();

    public boolean apply(AnPacket packet);
}
