
package org.owasp.java.policysnoop;

import java.util.*;
import java.io.*;


public class ExecutionStack
{

	private String[][] myStack = null;
	private Throwable myThrowable = new Throwable();

	public ExecutionStack()
	{
		myStack = getCurrentStack();
	}



	private String[][] getCurrentStack()
	{
		int skipTop = 0;
		int skipBottom = 0;

		String[] entries = getStackEntries();

		String[][] stack = new String[ entries.length - (skipTop + skipBottom) ][];
		for ( int loop = skipTop; loop < entries.length - skipBottom; loop++ )
		{
			String[] entry = parseStackEntry( entries[ loop ] );
			stack[ loop-skipTop ] = entry;
		}
		return( stack );
	}


	/**
	* This method returns the stack trace of the current thread.
	* @return an array containing the contents of the stack trace.
	*/
	private String[] getStackEntries()
	{
		// FIXME: this may be platform dependent.
		myThrowable.fillInStackTrace();
		CharArrayWriter data = new CharArrayWriter();
		PrintWriter out = new PrintWriter(data);

		myThrowable.printStackTrace(out);
		out.flush();
		out.close();

		StringTokenizer lt = new StringTokenizer( data.toString(), "\r\n" );

		Vector vector = new Vector();
		lt.nextToken(); // FIXME: not very safe -- skip the Exception text itself.
		while ( lt.hasMoreTokens() )
		{
			vector.addElement( lt.nextToken() );
		}
		String[] stackTrace = new String[ vector.size() ];
		vector.copyInto( stackTrace );
		return( stackTrace );
	}


	private String[] parseStackEntry( String line )
	{
		String fqn;
		String classname;
		String methodname;
		String filename;
		String linenumber;
		String skip;

		String[] results = null;

		try
		{
			StringTokenizer wt = new StringTokenizer( line, " \t\r\n():" );
			skip = wt.nextToken();  // skip the "at"

			fqn = wt.nextToken();
			int index = fqn.lastIndexOf( '.' );
			classname = fqn.substring( 0, index );
			methodname = fqn.substring( index+1 );
			filename = wt.nextToken();
			linenumber = wt.nextToken();

			// if source file is not available
			if ( linenumber.endsWith( "Code" ) )
			{
				filename = "";
				linenumber = "";
			}

			results = new String[] { classname, methodname, filename, linenumber };
		}
		catch( Exception e )
		{
//			System.out.println( "Exception parsing stack trace: " + e );
//			System.out.println( "\t" + line );
			results = new String[] { " -- not available -- ", "", "", "" };
		}
		return( results );
	}

	public String getMainProgramName()
	{
		String name = formatEntry( myStack[ myStack.length - 1 ] );
		return( name );
	}

	public String[] getCheckPermissionCaller()
	{
		for ( int loop = 0; loop < myStack.length; loop++ )
		{
		    String[] entry = myStack[ loop ];
			if ( entry[0].equals( "InteractiveSecurityManager" ) && entry[1].equals( "checkPermission" ) )
			{
			    return( myStack[ loop + 2 ] );
			}
		}
		return( null );
	}

	public String formatEntry( String[] entry )
	{
		StringBuffer result = new StringBuffer();
		result.append( "\t" );
		result.append( entry[0] ); // classname
		result.append( "." );
		result.append( entry[1] + "()" ); // methodname
		if ( entry[2].length() > 0 )
		{
			result.append( "-" );
			result.append( entry[2] ); // source filename
			result.append( "(" );
			result.append( entry[3] ); // source linenumber
			result.append( ")" );
		}
		return( result.toString() );
	}

	public String toDetailedString()
	{
		if ( myStack == null ) return( "null" );
		StringBuffer sb = new StringBuffer();
		sb.append( "ExecutionStack(" + myStack.length + ")\n" );
		for ( int loop = 0; loop < myStack.length; loop++ )
		{
			sb.append( "\t" + formatEntry( myStack[ loop ] ) + "\n" );
		}
		return( sb.toString() );
	}


	public String toString()
	{
		if ( myStack == null ) return ( "null" );
		String result = "stack(" + myStack.length + ")";
		return( result );
	}
}
