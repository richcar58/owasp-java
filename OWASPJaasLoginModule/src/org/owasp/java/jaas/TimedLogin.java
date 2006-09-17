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
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;
import java.util.Vector;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
/**
 *
 * @author stephen
 */
public class TimedLogin extends DBLogin {
    private String loginTable;
    private int clippingLevel=0;
    private int interval=0; //In seconds
    
    protected synchronized Vector validateUser(String username, char password[]) throws LoginException {
        
        ResultSet rsu = null, rsa = null, rsr = null;
        Connection con = null;
        PreparedStatement psu = null, psa = null, psr = null;
        Date timeStamp = null;
        int failedLogins=0;
        String cryptPassword = null;
        Calendar permittedLoginTime;
        
        try {
            Class.forName(dbDriver);
            if (dbUser != null)
                con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            else
                con = DriverManager.getConnection(dbURL);
            
            psu = con.prepareStatement("SELECT UserID,Password FROM " + userTable + " WHERE UserName=?");
            
            psu.setString(1, username);
            rsu = psu.executeQuery();
            if (!rsu.next()) throw new AccountNotFoundException("Unknown user");
            int uid = rsu.getInt(1);
            String realPassword = rsu.getString(2);
            psa = con.prepareStatement("SELECT UserID,Timestamp,FailedLogins FROM " + loginTable + " WHERE UserID=?");
            psa.setInt(1, uid);
            rsa = psa.executeQuery();
            while (rsa.next()) {
                timeStamp = rsa.getTimestamp(2);       
                failedLogins = rsa.getInt(3);
            }
            if (timeStamp != null) {
                Date now = new Date();
                if (now.before(timeStamp)) {
                    throw new AccountLockedException("Login only permitted after: "+timeStamp.toString());
                }
            }
            
            try {
                cryptPassword = new String(Utils.cryptPassword(password));
            } catch (Exception e) {
                throw new LoginException("Error encoding password (" + e.getMessage() + ")");
            }
            if (cryptPassword.equals(realPassword)) {
                Vector p = new Vector();
                p.add(new TypedPrincipal(username, TypedPrincipal.USER));
                psr = con.prepareStatement("SELECT " + roleTable + ".RoleName FROM " +
                        roleMapTable + "," + roleTable +
                        " WHERE " + roleMapTable + ".UserID=? AND " +
                        roleMapTable + ".RoleID=" + roleTable + ".RoleID");
                psr.setInt(1, uid);
                rsr = psr.executeQuery();
                while (rsr.next()) {
                    p.add(new TypedPrincipal(rsr.getString(1), TypedPrincipal.GROUP));
                }
                updateSuccessfulLogin(con, uid);
                return p;
                
            } else {
                updateFailedLogin(con, uid, failedLogins);
                throw new FailedLoginException("Bad password");
                
            }           
            
        } catch (ClassNotFoundException e) {
            System.out.println("SQL ERROR 1");
            e.printStackTrace();
            throw new LoginException("Error reading database (" + e.getMessage() + ")");
        } catch (SQLException e) {
            System.out.println("SQL ERROR");
            e.printStackTrace();
            throw new LoginException("Error reading database (" + e.getMessage() + ")");
        } finally {
            try {
                if (rsu != null) rsu.close();
                if (rsa != null) rsa.close();
                if (psu != null) psu.close();
                if (psa != null) psa.close();
                if (con != null) con.close();
            } catch (Exception e) { }
        }
    }
        
    protected void updateFailedLogin(Connection con, int userID, int failedLogins) throws LoginException {
        PreparedStatement psu=null;
        failedLogins = failedLogins+1;
        try {
            if (failedLogins >= clippingLevel) {                
                psu = con.prepareStatement("UPDATE " + loginTable + " SET Timestamp=?,FailedLogins=? WHERE UserID=?");
                Date now = new Date();
                int increment=((failedLogins-clippingLevel)*interval)+interval;
                java.sql.Timestamp newStamp = new java.sql.Timestamp(now.getTime()+(increment*1000));
                psu.setTimestamp(1, newStamp);
                
                psu.setInt(2, failedLogins);
                psu.setInt(3, userID);
            } else {
                
                psu = con.prepareStatement("UPDATE " + loginTable + " SET FailedLogins=? WHERE UserID=?");
                psu.setInt(1, failedLogins);
                psu.setInt(2, userID);
            }
            int rows = psu.executeUpdate();
            if (rows == 0) throw new LoginException("Error updating the "+loginTable+" with failed login details.");
            
        } catch (SQLException e) {
            throw new LoginException("Error reading database (" + e.getMessage() + ")");
        } finally {
            try {
                if (psu != null) psu.close();
            } catch (Exception e) { }
        }
    }
    
    protected void updateSuccessfulLogin(Connection con, int userID) throws LoginException {
        PreparedStatement psu=null;
        try {
            psu = con.prepareStatement("UPDATE " + loginTable + " SET Timestamp=?,FailedLogins=? WHERE UserID=?");
            Date now = new Date();
            psu.setTimestamp(1, new java.sql.Timestamp(now.getTime()));
            psu.setInt(2, 0); 
            psu.setInt(3, userID);  
            psu.executeUpdate();            
        } catch (SQLException e) {
            throw new LoginException("Error reading database (" + e.getMessage() + ")");
        } finally {
            try {
                if (psu != null) psu.close();
            } catch (Exception e) { }
        }
    }
    
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        
        loginTable  = getOption("loginTable",    "login");
        interval = getOption("interval",    180);
        clippingLevel = getOption("clippingLevel",    1);
    }
    
    /** Creates a new instance of TimedLoginModule */
    public TimedLogin() {
    }
    
}
