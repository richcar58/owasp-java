/*
 * RolePrincipal.java
 *
 * Created on 16 de octubre de 2006, 19:28
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package org.owasp.java.jaas;

import com.tagish.auth.TypedPrincipal;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 *
 * This class exists purely because Tomcat requires another class to hold Role principals.
 */
public class RolePrincipal extends TypedPrincipal{
    private static Logger logger = Logger.getLogger("org.owasp.java.jaas.RolePrincipal");
    
    /** Creates a new instance of RolePrincipal */
    public RolePrincipal() {
    }
    
    public RolePrincipal(String name, int type)	{
        super(name, type);
        
    }
    
    
    public RolePrincipal(String name) {
        this(name, UNKNOWN);
    }
    
}
