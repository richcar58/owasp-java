/*
 * AuthorisationTest.java
 * JUnit based test
 *
 * Created on September 17, 2006, 11:41 AM
 */

package org.owasp.java.jaas.loginmodule.test;

import com.tagish.auth.test.PasswordCallbackHandler;
import java.io.FileInputStream;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.AccessControlException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Iterator;
import javax.security.auth.Subject;
import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.LoginContext;
import org.dbunit.DatabaseTestCase;
import org.dbunit.database.DatabaseConnection;
import org.dbunit.database.IDatabaseConnection;
import org.dbunit.dataset.IDataSet;
import org.dbunit.dataset.xml.FlatXmlDataSet;
import org.dbunit.operation.DatabaseOperation;
import org.owasp.java.jaas.sample.SampleAction;

/**
 *
 * @author stephen
 */
public class AuthorisationTest extends DatabaseTestCase {
    private final String validUsername="bob";
    private final int validUserID=1;
    private final String validPassword="password";
    
    private final String dbDriver = "org.hsqldb.jdbcDriver";
    private final String dbUrl = "jdbc:hsqldb:hsql://localhost/jaastestdb";
    private final String dbUsername = "sa";
    private final String dbPassword = "";
    
    public AuthorisationTest(String testName) {
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
    
    public void testPrincipals() {
        try {            
            LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, validPassword));;
            lc.login();
            Subject mySubject = lc.getSubject();
            // let's see what Principals we have
            Iterator principalIterator = mySubject.getPrincipals().iterator();
            boolean foundUser=false;
            boolean foundRole=false;
            while (principalIterator.hasNext()) {
                Principal p = (Principal)principalIterator.next();
                if ("bob".equals(p.getName())) foundUser=true;
                if ("User".equals(p.getName())) foundRole=true;
            }
            assertTrue("Did not find principal bob", foundUser);
            assertTrue("Did not find principal User(role)", foundRole);
        } catch (AccountNotFoundException e) {
            fail(validUsername+ " should be a valid user.");
        } catch (Exception other) {
            fail("Unexpected exception thrown: "+other.getMessage());
        }
        
    }
    
    public void testValidAccess() {
        String filename="user.txt";
        try {
            
            LoginContext lc = new LoginContext("Example", new PasswordCallbackHandler(validUsername, validPassword));;
            lc.login();
            Subject mySubject = lc.getSubject();
            SampleAction action = new SampleAction();            
            action.setFilename(filename);
            Subject.doAsPrivileged(mySubject, action, null);            
        } catch (AccountNotFoundException e) {
            fail(validUsername+ " should be a valid user.");
        } catch (AccessControlException ace) {
            fail ("Access was denied to file: "+filename);
        } catch (Exception other) {
            fail("Unexpected exception thrown: "+other.getMessage());
        } 
        
    }
}
