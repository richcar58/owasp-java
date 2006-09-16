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
import com.tagish.auth.test.PasswordCallbackHandler;
import com.tagish.auth.test.LoginCallbackHandler;
import com.tagish.auth.Utils;
import java.sql.SQLException;
import javax.security.auth.login.FailedLoginException;

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
        int count=0;
        while ((!loggedIn) && (count<10)) {
            try {
                
                //LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler("bob", "1password"));
                LoginContext lc = new LoginContext("Example", new LoginCallbackHandler());
                lc.login();
                System.out.println("Login successful");
            } catch (Exception e) {
                System.out.println("Error logging in");
                e.printStackTrace();
            }
            count++;
        }
        try {
                
                LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler("bob", "password"));
                //LoginContext lc = new LoginContext("Example", new LoginCallbackHandler());
                lc.login();
                System.out.println("Login successful");
            } catch (Exception e) {
                System.out.println("Error logging in");
                e.printStackTrace();
            }
    }
    
}
