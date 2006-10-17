/*
 * AuthorisationTest.java
 * JUnit based test
 *
 * Created on September 17, 2006, 11:41 AM
 */

package org.owasp.java.jaas.tomcatloginmodule;

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
public class RolesTest extends DatabaseTestCase {
    private final String validUsername="bob";
    private final int validUserID=1;
    private final String validPassword="password";
    
    private final String dbDriver = "org.hsqldb.jdbcDriver";
    private final String dbUrl = "jdbc:hsqldb:hsql://localhost/jaastestdb";
    private final String dbUsername = "sa";
    private final String dbPassword = "";
    
    public RolesTest(String testName) {
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
    
   
    
     public void testRoles() {
        try {            
            LoginContext lc = new LoginContext("TomcatTimedLogin", new PasswordCallbackHandler(validUsername, validPassword));;
            lc.login();
            Subject mySubject = lc.getSubject();
            // let's see what Principals we have
            Iterator principalIterator = mySubject.getPrincipals().iterator();

            while (principalIterator.hasNext()) {
                Principal p = (Principal)principalIterator.next();
                if ("User".equals(p.getName())) {
                    assertEquals("Role is not of the correct type", org.owasp.java.jaas.RolePrincipal.class.getName(), p.getClass().getName());
                }
            }
            
        } catch (AccountNotFoundException e) {
            fail(validUsername+ " should be a valid user.");
        } catch (Exception other) {
            fail("Unexpected exception thrown: "+other.getMessage());
        }
        
    }
    
    
}
