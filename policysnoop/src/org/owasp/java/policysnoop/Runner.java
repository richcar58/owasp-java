package org.owasp.java.policysnoop;

import java.io.*;
import java.net.*;
import java.lang.reflect.*;
import java.security.*;
import java.util.*;

public class Runner
{
    private static ThreadGroup untrusted;

    public static void init( ThreadGroup tg )
    {
        untrusted = tg;
    }
    
    // run the class in its own thread    
    private static Thread runthread;
    public static void run( final String clazz, final String[] args, String classpath )
    {
        if ( runthread != null && runthread.isAlive() )
        {
            try
            {
                runthread.stop();     // yes it's deprecated
            }
            catch( Exception e )
            {
                // do nothing it's probably dead
            }
            finally
            {
                runthread = null;
            }
        }
        runthread = new RunnerThread( untrusted, "Snoop", clazz, args, classpath );
        runthread.start();
    }
    

}
