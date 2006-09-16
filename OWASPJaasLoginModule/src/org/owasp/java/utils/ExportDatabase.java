/*
 * ExportDatabase.java
 *
 * Created on September 16, 2006, 10:25 AM
 *
 */

package org.owasp.java.utils;

import java.io.FileOutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import org.dbunit.database.DatabaseConnection;
import org.dbunit.database.IDatabaseConnection;
import org.dbunit.dataset.IDataSet;
import org.dbunit.dataset.xml.FlatDtdDataSet;
import org.dbunit.dataset.xml.FlatXmlDataSet;

public class ExportDatabase
{
    public static void main(String[] args) throws Exception
    {
        // database connection
        Class driverClass = Class.forName("org.hsqldb.jdbcDriver");
        Connection jdbcConnection = DriverManager.getConnection(
                "jdbc:hsqldb:hsql://localhost/jaastestdb", "sa", "");
        IDatabaseConnection connection = new DatabaseConnection(jdbcConnection);

        // write DTD file
        FlatDtdDataSet.write(connection.createDataSet(),new FileOutputStream("jaastestdb.dtd"));
        // full database export
        IDataSet fullDataSet = connection.createDataSet();
        FlatXmlDataSet.write(fullDataSet, new FileOutputStream("jaastestdb.xml"));
    }
    
}