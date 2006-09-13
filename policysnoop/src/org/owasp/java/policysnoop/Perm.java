
package org.owasp.java.policysnoop;

import java.security.*;
import java.util.*;
  
public class Perm
{
    private static int number = 0;
    private int mode = PolicyModel.DEFAULT;
    
    private Grant myGrant;
    private String name;
    private String type;
    private String object;
    private Vector actions;
    private int count = 1;
    
    public Perm( Grant g, Permission p )
    {
        this( "perm" + number++, g, p );
    }
    
    public Perm( String name, Grant g, Permission p )
    {
        this.name = name;
        this.myGrant = g;
 		String classname = p.getClass().getName();
        this.type = classname.substring( classname.lastIndexOf( '.' ) + 1 );
        this.object = unslash( p.getName() );
        this.actions = parseActions( p.getActions() );
    }
    
    private Vector parseActions( String actions )
    {
        Vector v = new Vector();
        StringTokenizer st = new StringTokenizer( actions, "," );
        while ( st.hasMoreElements() )
        {
            String token = (String)st.nextElement();
            v.add( token );
        }
        return( v );
    }
    
    public String getName()
    {
        return( name );
    }

    public Vector getActions()
    {
        return( actions );
    }
 
    public String getObject()
    {
        return( object );
    }
 
    public String getType()
    {
        return( type );
    }
 
    
    public boolean isMode( int m )
    {
        return( mode == m );
    }
    
    public void setMode( int m )
    {
        mode = m;
    }
    
    
    public void use()
    {
        System.out.println( "using " + this );
        count++;
    }
    
    public int getUseCount()
    {
        return( count );
    }
    
    public boolean implies( Perm p )
    {
        // types must be equal
        if ( !( p.getType().equals( this.getType() ) ) ) return( false );

        // this.actions contains all of the actions in p
        // FIXME: special case ALL
        Iterator i = p.getActions().iterator();
        while( i.hasNext() )
        {
            String action = (String)i.next();
            if ( !this.actions.contains( action ) ) return( false );
        }
       
        // p.object is a subset of this.object
        if ( !implies( this.object, p.getObject() ) ) return( false );
        
        return( true );
    }

    // Trailing "" is illegal
    // Trailing "/" matches all class files (not JAR files) in the specified directory
    // Trailing "/*" matches all files (both class and JAR files) contained in that directory
    // Trailing "/-" matches all files (both class and JAR files) in the directory and recursively all files in subdirectories
    public boolean implies( String longBase, String shortBase )
    {
        boolean implied = false;
        
        if ( longBase.equals( shortBase ) ) return( true );
        
        else if ( shortBase.endsWith( "/" ) )
        {
            String shortTrim = shortBase.substring( 0, shortBase.length()-2 );
            if ( longBase.startsWith( shortTrim ) )
            {
                // check to make doesn't end in ".jar" or ".zip"
                if ( !longBase.endsWith( ".jar" ) || !longBase.endsWith( ".zip" ) ) implied = true;
            }
        }
        else if ( shortBase.endsWith( "/*" ) )
        {
            String shortTrim = shortBase.substring( 0, shortBase.length()-3 );
            if ( longBase.startsWith( shortTrim ) )
            {
                // check to make sure no additional slashes
                String trailer = longBase.substring( shortBase.length()-2 );
                if ( trailer.indexOf( "/" ) != -1 ) implied = true;
            }
        }
        else if ( shortBase.endsWith( "/-" ) )
        {
            String shortTrim = shortBase.substring( 0, shortBase.length()-3 );
            if ( longBase.startsWith( shortTrim ) ) implied = true;
        }
        return( implied );
    }

    private String checkCodeBase( String codeBase )
    {
        if ( !codeBase.endsWith( "/" ) || !codeBase.endsWith( "/*" ) || !codeBase.endsWith( "/-" ) )
        {
            codeBase += "/";
        }
        return( codeBase );
    }




    private String unslash( String string )
    {
        StringBuffer sb = new StringBuffer();
        for ( int loop=0; loop<string.length(); loop++ )
        {
            char c = string.charAt( loop );
            if ( c == '\\' ) sb.append( '/' );
            else sb.append( c );
        }
        return( sb.toString() );
    }
    

    public String toString()
    {
        StringBuffer sb = new StringBuffer();
        sb.append( type + " \"" + object + "\"" );
        if ( actions != null && actions.size() > 0 )
        {
            sb.append( ", \"" );
            Iterator i = actions.iterator();
            while( i.hasNext() )
            {
                String action = (String)i.next();
                sb.append( action );
                if ( i.hasNext() ) sb.append( "," );
            }
            sb.append( "\"" );
        }
        sb.append( "; // (" + count + ")" );
        return( sb.toString() );
     }
    
}