/*
 * Standalone.java
 *
 * Created on September 11, 2006, 7:33 PM
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package org.owasp.java.jaas;

import javax.security.auth.login.LoginContext;
import com.tagish.auth.test.LoginCallbackHandler;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Iterator;
import javax.security.auth.Subject;
import org.owasp.java.jaas.sample.SampleAction;

/**
 *
 * @author stephen
 */
public class Standalone {
    
    /** Creates a new instance of Standalone */
    public Standalone() {
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        boolean loggedIn = false;
        LoginContext lc=null;
        System.out.println("Enter your username and password");
        
        while (!loggedIn) {
            try {                
                lc = new LoginContext("Example", new LoginCallbackHandler());
                lc.login();
                loggedIn = true;
            } catch (Exception e) {
                System.out.println("Error logging in");
                e.printStackTrace();
            }

        }
        System.out.println("Authentication succeeded!");

	Subject mySubject = lc.getSubject();

	// let's see what Principals we have
	Iterator principalIterator = mySubject.getPrincipals().iterator();
	System.out.println("Authenticated user has the following Principals:");
	while (principalIterator.hasNext()) {
	    Principal p = (Principal)principalIterator.next();
	    System.out.println("\t" + p.toString());
	}

	System.out.println("User has " +
			mySubject.getPublicCredentials().size() +
			" Public Credential(s)");

	// now try to execute the SampleAction as the authenticated Subject
	PrivilegedAction action = new SampleAction();
	Subject.doAsPrivileged(mySubject, action, null);
	System.exit(0);
        
    }
    
}
