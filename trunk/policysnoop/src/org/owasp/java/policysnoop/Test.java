package org.owasp.java.policysnoop;

import java.io.*;
import java.util.Hashtable;
import java.net.InetAddress;
import java.lang.reflect.Member;
import java.util.*;
import java.text.*;
import javax.swing.*;


/**
 * A program which randomly attempts to create files, read files, delete files,
 * create server sockets, create client sockets, and exit the Java VM.
 */
class Test
{

	// try to create a file
	public static void createFile() throws Throwable
	{
		System.out.println( "\nAttempting to create a file called test.log" );
		java.io.FileWriter fw = new java.io.FileWriter( new java.io.File( "c:\\temp", "test.log" ) );
	}

	// try to read a file
	public static void readFile() throws Throwable
	{
		System.out.println( "\nAttempting to read a file called test.log" );
		java.io.FileReader fr = new java.io.FileReader( new java.io.File( "c:\\temp", "test.log" ) );
	}

	// try to delete a file
	public static void deleteFile() throws Throwable
	{
		System.out.println( "\nAttempting to delete a file called test.log" );
		new java.io.File( "c:\\temp", "test.log" ).delete();
	}

	// try to create a server socket on port 21
	public static void createServer() throws Throwable
	{
		System.out.println( "\nAttempting to create a server socket on port 21" );
		java.net.ServerSocket server = new java.net.ServerSocket( 21 );
	}

	// try to create a client socket on port 21
	public static void createClient() throws Throwable
	{
		System.out.println( "\nAttempting to create a client socket on port 21" );
		java.net.Socket client = new java.net.Socket( "localhost", 21 );
	}

	// try to exit the JVM with status 65536
	public static void exit() throws Throwable
	{
//		System.out.println( "\nAttempting to exit the JVM with status 65536" );
//		System.exit( 65536 );
	}


	public static void doRandomCommand() throws Throwable
	{
		int commandCount = 6; // remember to count 0
		int command = (int)( Math.random() * commandCount );
		switch( command )
		{
			case 0:
				createFile();
				break;
			case 1:
				readFile();
				break;
			case 2:
				deleteFile();
				break;
			case 3:
				createClient();
				break;
			case 4:
				createServer();
				break;
			case 5:
				exit();
				break;
			default:
				System.out.println( "Bad command number: " + command );
				break;
		}
	}


	public static void main( String args[] )
	{
	    System.out.println( "Starting Test.main()" );
		// now do some stuff to force security manager calls
		while( true )
		{
			try
			{
				Test2.doRandomCommand();
				Thread.sleep( 500 );
			}
			catch( Exception e )
			{
				System.out.println( "\tCaught exception " + e );
//				e.printStackTrace();
			}
		}
	}

}