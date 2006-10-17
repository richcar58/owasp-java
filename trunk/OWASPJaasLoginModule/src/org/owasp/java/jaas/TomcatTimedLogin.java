/*
 * TimedLoginModule.java
 *
 * Created on September 13, 2006, 12:50 PM
 *
 */

package org.owasp.java.jaas;

import java.security.Principal;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

/**
 *
 * @author stephen
 */
public class TomcatTimedLogin extends TimedLogin {
    private String loginTable;
    private String loginQuery;
    private String rolesQuery;
    private int clippingLevel=0;
    private int interval=0; //In seconds
    private static Logger logger = Logger.getLogger("org.owasp.java.jaas.TomcatTimedLogin");
        
    protected Principal createRolePrincipal(String name, int type) {
        logger.log(Level.FINE, "Adding new RolePrincipal ("+name+")");
        return new RolePrincipal(name, type);
    }
    
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        if (debug) logger.setLevel(Level.FINE);
    }
    
}
