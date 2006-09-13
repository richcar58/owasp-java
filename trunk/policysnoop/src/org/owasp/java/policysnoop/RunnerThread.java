package org.owasp.java.policysnoop;

import java.io.*;
import java.net.*;
import java.lang.reflect.*;
import java.security.*;
import java.util.*;

public class RunnerThread extends Thread
{

    private static boolean trusted = true;
    String clazz;
    String[] args;
    String classpath;
    
    public RunnerThread( ThreadGroup parent, String name, String clazz, String[] args, String classpath )
    {
        super( parent, name );
        this.clazz = clazz;
        this.args = args;
        this.classpath = classpath;
    }
    
    public boolean isTrusted()
    {
        return( trusted );
    }

    public void run()
    {
        invokeMain( clazz, args, classpath );
    }
    
    // args[0] is className, the rest are parameters
	private static void invokeMain( String clazz, String[] args, String classpath )
	{
	    // set thread to be trusted until we invoke main
	    trusted = true;
	    
		SnoopManager sm = (SnoopManager)System.getSecurityManager();
		try
		{
            // load the target class with a loader that fills in the ProtectionDomain
            URL[] urls = toURLArray( classpath );
            Class target = getClassLoader( urls ).loadClass( clazz );

            // find a method with the main( String[]s args ) signature
            Class argList[] = new Class[] { String[].class };
            Method mainMethod = target.getMethod( "main", argList );

            // get around namespace access control -- sheesh
            mainMethod.setAccessible( true );

            // wrap up all the arguments
            Object wrapArgs[] = new Object[1];
            wrapArgs[0] = args;
            
            // set thread to be untrusted before invoking main
            trusted = false;
            
            // invoke the main method
            mainMethod.invoke( null, wrapArgs );  // static main so null okay
		}
		catch( ClassNotFoundException cnfe )
		{
			System.out.println( "Can't find class " + clazz );
		}
		catch( NoSuchMethodException nsme )
		{
			System.out.println( "Can't find main( String[] args ) method in " + clazz );
		}
		catch( ThreadDeath td )
		{
		    // great! it died
		}
		catch( Exception e )
		{
		    System.out.println( "Unknown exception" );
		    e.printStackTrace();
		}
	}


    public static URL[] toURLArray( String classpath ) throws MalformedURLException
    {
        Vector items = new Vector();
        StringTokenizer st = new StringTokenizer( classpath );
        while ( st.hasMoreTokens() )
        {
            String token = st.nextToken();
            items.add( new URL( "file:" + token ) );
        }
        URL[] urls = (URL[])items.toArray( new URL[0] );
        return( urls );
    }            


    private static ClassLoader getClassLoader( URL[] urls )
    {
        ClassLoader loader = null;
        try
        {
            loader = new URLClassLoader( urls )
            {
                // find and resolve the class locally, otherwise ask the primordial classloader
                // NOTE: this breaks the Java2 delegation model on purpose
                protected synchronized Class loadClass(String name, boolean resolve) throws ClassNotFoundException
                {
                    Class c;
                    try
                    {
	                    c = findClass(name);
	                    resolveClass(c);
	                }
	                catch( Exception e )
	                {
		                c = super.loadClass( name, resolve );
		            }
		            return( c );
                }
            };
        }
        catch( Exception e )
        {
            System.out.println( "Couldn't create classloader" );
            e.printStackTrace();
            System.exit( -1 );
        }
        return( loader );
    }        
    
}
