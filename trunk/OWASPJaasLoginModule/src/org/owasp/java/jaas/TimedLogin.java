/*
 * TimedLoginModule.java
 *
 * Created on September 13, 2006, 12:50 PM
 *
 */

package org.owasp.java.jaas;

import com.tagish.auth.DBLogin;
import com.tagish.auth.TypedPrincipal;
import com.tagish.auth.Utils;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Vector;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
/**
 *
 * @author stephen
 */
public class TimedLogin extends DBLogin {
    private String auditTable;
    
    protected synchronized Vector validateUser(String username, char password[]) throws LoginException {
        
        return (validateUserAgainstDatabase(username, password));
    }
    
    protected synchronized boolean isLockedOut (String username) throws LoginException{
        ResultSet rsu = null, rsa = null;
        Connection con = null;
        PreparedStatement psu = null, psa = null;
        
        try {
            Class.forName(dbDriver);
            if (dbUser != null)
                con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            else
                con = DriverManager.getConnection(dbURL);
            
            psu = con.prepareStatement("SELECT UserID FROM " + userTable + " WHERE UserName=?" + where);
            psa = con.prepareStatement("SELECT * FROM " + auditTable + " WHERE UserID=?");
            
            psu.setString(1, username);
            rsu = psu.executeQuery();
            if (!rsu.next()) throw new FailedLoginException("Unknown user");
            int uid = rsu.getInt(1);
            psa.setInt(1, uid);
            rsa = psa.executeQuery();
            Vector auditTrail = new Vector();
            while (rsa.next()) {
                rsa.getString(1);
            }
        } catch (ClassNotFoundException e) {
            throw new LoginException("Error reading user database (" + e.getMessage() + ")");
        } catch (SQLException e) {
            throw new LoginException("Error reading user database (" + e.getMessage() + ")");
        } finally {
            try {
                if (rsu != null) rsu.close();
                if (rsr != null) rsr.close();
                if (psu != null) psu.close();
                if (psr != null) psr.close();
                if (con != null) con.close();
            } catch (Exception e) { }
        }
    }
    
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        
        auditTable  = getOption("auditTable",    "audit");
    }
    
    
    /** Creates a new instance of TimedLoginModule */
    public TimedLogin() {
    }
    
}
