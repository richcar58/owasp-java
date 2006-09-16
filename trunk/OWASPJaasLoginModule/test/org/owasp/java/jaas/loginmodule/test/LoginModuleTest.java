/*
 * LoginModuleTest.java
 * JUnit based test
 *
 * Created on September 11, 2006, 10:59 PM
 */

package org.owasp.java.jaas.loginmodule.test;

import com.tagish.auth.test.PasswordCallbackHandler;
import java.io.FileInputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;
import org.dbunit.DatabaseTestCase;
import org.dbunit.database.DatabaseConnection;
import org.dbunit.database.IDatabaseConnection;
import org.dbunit.dataset.IDataSet;
import org.dbunit.dataset.xml.FlatXmlDataSet;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.LoginContext;
import org.dbunit.operation.DatabaseOperation;

/**
 *
 * @author stephen
 */
public class LoginModuleTest extends DatabaseTestCase {
    //These values must match those in the login configuration file
    private final int clippingLevel=3;
    private final int interval = 10; //seconds
    private final String validUsername="bob";
    private final int validUserID=1;
    private final String validPassword="password";
    
    private final String dbDriver = "org.hsqldb.jdbcDriver";
    private final String dbUrl = "jdbc:hsqldb:hsql://localhost/jaastestdb";
    private final String dbUsername = "sa";
    private final String dbPassword = "";
    
    public LoginModuleTest(String testName) {
        super(testName);
    }
    
    protected IDatabaseConnection getConnection() throws Exception {
        Class driverClass = Class.forName(dbDriver);
        Connection jdbcConnection = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
        return new DatabaseConnection(jdbcConnection);
    }
    
    protected IDataSet getDataSet() throws Exception {
        return new FlatXmlDataSet(new FileInputStream("jaastestdb.xml"));
    }
    
    protected void setUp() throws Exception {
        super.setUp();
        
        IDatabaseConnection connection = getConnection();
        IDataSet dataSet = getDataSet();
        try {
            DatabaseOperation.CLEAN_INSERT.execute(connection, dataSet);
        } finally {
            connection.close();
        }
    }
    
    protected void tearDown() throws Exception {
    }
    
    public void testBadUsername() {
        try {
            
            LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler("noone", validPassword));
            //LoginContext lc = new LoginContext("Example", new LoginCallbackHandler());
            lc.login();
            fail("AccountNotFoundException was not thrown");
        } catch (AccountNotFoundException e) {
            
        } catch (Exception other) {
            fail("AccountNotFoundException should have been thrown, instead we get:"+other.getMessage());
        }
    }
    
    public void testBadPasswordOnce() {
        try {
            
            LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, "badpassword"));
            //LoginContext lc = new LoginContext("Example", new LoginCallbackHandler());
            lc.login();
            fail("Login should not have succeeded");
        } catch (FailedLoginException fle) {
            
        } catch (Exception other) {
            fail("FailedLoginException should have been thrown, instead we get:"+other.getMessage());
        }
    }
    
    public void testTimerActivated() {
        for (int i=1;i<6;i++){
            try {
                LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, "badpassword"));
                
                lc.login();
                fail("Login should not have succeeded");
            } catch (FailedLoginException fle) {
                //System.out.println("clipping="+Integer.toString(clippingLevel)+" i="+Integer.toString(i));
                assertTrue("Failedlogin should only occur below the clipping level",i<=clippingLevel);
            } catch (AccountLockedException ale) {
                assertTrue("Account should be locked out on the 4th attempt.",i>clippingLevel);
                
            } catch (Exception other) {
                fail("FailedLoginException or AccountLockedException should have been thrown, instead we get:"+other.toString());
            }
        }
    }
    
    public void testLockoutAndTimeoutValues() {
        Date now=null;
        Connection con=null;
        ResultSet rs=null;
        PreparedStatement ps=null;
        for (int i=1;i<=clippingLevel+1;i++){
            try {
                now = new Date();
                LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, "badpassword"));
                lc.login();
                
                fail("Login should not have succeeded");
            } catch (FailedLoginException fle) {
                assertTrue("Failedlogin should only occur below the clipping level",i<=clippingLevel);
            } catch (AccountLockedException ale) {
                assertEquals("Account should be locked out on the 4th attempt.",i,clippingLevel+1 );
            } catch (Exception other) {
                fail("FailedLoginException or AccountLockedException should have been thrown, instead we get:"+other.toString());
            }
        }
        try {
            Class.forName(dbDriver);
            con = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
            ps = con.prepareStatement("SELECT Timestamp,FailedLogins FROM login WHERE UserID=?");
            ps.setInt(1, validUserID);
            rs = ps.executeQuery();
            assertTrue("Login record not found.",rs.next());
            long timestamp = rs.getTimestamp(1).getTime();
            long diffSeconds = (timestamp-now.getTime())/1000;
            //Can be off by at most 1 second
            assertTrue("Time difference should be "+Integer.toString(interval)+" but is "+Long.toString(diffSeconds), ((diffSeconds>=interval-1) && (diffSeconds<=interval+1)));
     
            int failedAttempts = rs.getInt(2);
            assertEquals("Failed attempts not correct", clippingLevel, failedAttempts);
            //Now wait until the timeout passes so we can try again
            Thread.sleep(interval*1000);
            LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, "badpassword"));
            lc.login();
            fail("Should have thrown a failed login exception");
        } catch (AccountLockedException fle) {
            fail("The account should not be locked anymore");
        } catch (FailedLoginException fle) {
            
        } catch (ClassNotFoundException e) {
            fail("Error reading database (" + e.getMessage() + ")");
        } catch (SQLException e) {
            fail("Error reading database (" + e.getMessage() + ")");
        } catch (Exception e) {
            fail("Unexpected exception: "+e.toString());
        } finally {
            try {
                if (rs != null) rs.close();
                if (ps != null) ps.close();
                if (con != null) con.close();
            } catch (Exception e) { }
        }
        
    }
    
    public void testSuccessfullAuthAfterLockout() {
        Date now=null;
        Connection con=null;
        ResultSet rs=null;
        PreparedStatement ps=null;
        for (int i=1;i<=clippingLevel+1;i++){
            try {
                
                LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, "badpassword"));
                lc.login();
                
                fail("Login should not have succeeded");
            } catch (FailedLoginException fle) {
                assertTrue("Failedlogin should only occur below the clipping level",i<=clippingLevel);
            } catch (AccountLockedException ale) {
                assertEquals("Account should be locked out on the 4th attempt.",i,clippingLevel+1 );
            } catch (Exception other) {
                fail("FailedLoginException or AccountLockedException should have been thrown, instead we get:"+other.toString());
            }
        }
        try {
            Thread.sleep(interval*1000);
            now = new Date();
            LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, validPassword));
            lc.login();
            
            Class.forName(dbDriver);
            con = DriverManager.getConnection(dbUrl, dbUsername, dbPassword);
            ps = con.prepareStatement("SELECT Timestamp,FailedLogins FROM login WHERE UserID=?");
            ps.setInt(1, validUserID);
            rs = ps.executeQuery();
            assertTrue("Login record not found.",rs.next());
            java.sql.Timestamp timestamp = rs.getTimestamp(1);
            
            assertTrue("Timeout value should be in the past", timestamp.before(now));
            int failedAttempts = rs.getInt(2);
            assertEquals("Failed attempts not correct", 0, failedAttempts);
            
        } catch (AccountLockedException fle) {
            fail("The account should not be locked anymore");
        } catch (FailedLoginException fle) {
            fail("The login should have succeeded");
        } catch (ClassNotFoundException e) {
            fail("Error reading database (" + e.getMessage() + ")");
        } catch (SQLException e) {
            fail("Error reading database (" + e.getMessage() + ")");
        } catch (Exception e) {
            fail("Unexpected exception: "+e.toString());
        } finally {
            try {
                if (rs != null) rs.close();
                if (ps != null) ps.close();
                if (con != null) con.close();
            } catch (Exception e) { }
        }
        
    }
    

        
    
}