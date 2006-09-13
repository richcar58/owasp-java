package org.owasp.java.policysnoop;

import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.lang.reflect.*;
import java.security.*;
import java.util.*;
import javax.swing.*;

public class PolicySnoop
{
    
	public static void main( String[] args )
	{
		// set the look and feel to windows
		try
		{
	        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
    	    // UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
			// UIManager.setLookAndFeel( "com.sun.java.swing.plaf.windows.WindowsLookAndFeel" );
		}
		catch( Exception e )
		{
			System.out.println( "Couldn't load new look and feel" );
		}

        // The Runner and SecurityManager must share a ThreadGroup
        ThreadGroup tg = new ThreadGroup( "UNTRUSTED" );
        Runner.init( tg );
        
        PolicyModel pm = new PolicyModel();
        PolicyGUI gui = new PolicyGUI( pm );  // direct access to PM
        
        pm.addPolicyListener( gui );  // notify gui of background model changes

		// Set the security manager for this VM
		System.setSecurityManager( new SnoopManager( pm, tg ) );
	}
    
}
