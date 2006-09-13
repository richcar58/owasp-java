
package org.owasp.java.policysnoop;

import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.lang.reflect.*;
import java.security.*;
import java.util.*;
import javax.swing.*;

public class SnoopManager extends SecurityManager
{
    
    private PolicyModel pm;
    private ThreadGroup untrusted;
    
    public SnoopManager( PolicyModel pm, ThreadGroup tg )
    {
        this.pm = pm;
        this.untrusted = tg;
    }
    
	public void checkPermission( Permission perm )
    {
        // System.out.println( "> " + perm );
        
        // special CTRL-C intercept
        // if ( perm instanceof RuntimePermission && perm.getName().equals( "modifyThread" ) )
        
        // shortcuts out for trusted threads
        // DANGER: this might allow actions executed by the AWT thread, for example
        Thread current = Thread.currentThread();
        if ( !( current instanceof RunnerThread ) ) return;
        if ( ((RunnerThread)current).isTrusted() ) return;
        if ( !untrusted.parentOf( current.getThreadGroup() ) ) return;
        
        // System.out.println( "   --> no shortcut" );
        
        // shortcut out for all PolicySnoop calls
        if ( inCheck() ) return;

        // System.out.println( "   --> not in check" );
        // System.out.println( new ExecutionStack().toDetailedString() );
                
		synchronized( pm )
		{
            pm.handle( perm, getCodeBase() );
        }
    }
    
    
    // search the stack for any calls from within this class
    // skip the top two for checkPermission() and inCheck()
    private boolean inCheck()
    {
        Class[] classes = getClassContext();
        
        // System.out.println( "=============================================" );
        // for ( int loop=0; loop < classes.length; loop++ ) System.out.println( "    > " + classes[loop] );
        
        // shortcut for threads already in a SecurityManager check
        // skip 0 and 1 since they're methods in this class
        for ( int loop=2; loop < classes.length; loop++ )
        {
            if ( classes[loop] == this.getClass() ) return( true );
        }
        return( false );
    }
    
    

    

    private String getCodeBase()
    {
        String codeBase = null;
        try
        {
            Class caller = getCaller();
            String callerName = caller.getName().substring( caller.getName().lastIndexOf( '.' ) + 1 );
            ProtectionDomain prot = caller.getProtectionDomain();
            if ( prot != null )
            {
                CodeSource source = prot.getCodeSource();
                if ( source != null )
                {
                    // java.security.cert.Certificate[] certs = source.getCertificates();
                    // if ( certs != null ) for ( int loop=0; loop< certs.length; loop++ )
                    //    System.out.println( "Cert:" + loop + ">" + certs[loop] );
                    URL location = source.getLocation();
                    codeBase = location + callerName + ".class";
                }
            }
        }
        catch( Exception e )
        {
            System.out.println( "Could not determine codeBase" );
        }
        return( codeBase );
    }
    
    
    
    // returns first class on stack that doesn't start with "java."
    private Class getCaller()
    {
        Class[] classes = getClassContext();
        for ( int loop=classes.length-3; loop >= 0; loop-- )  // skip the first two for PolicySnoop launching
        {
            String name = classes[loop].getName();
            if ( name.startsWith( "java." ) || name.startsWith( "javax." ) ) return( classes[loop+1] );
        }
        return( classes[classes.length-3] );
    }

}
