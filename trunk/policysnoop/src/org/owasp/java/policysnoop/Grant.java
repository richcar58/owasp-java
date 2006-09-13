package org.owasp.java.policysnoop;

import java.util.*; 
  
public class Grant
{

    private HashMap myStorage = new HashMap();
    
    private static int count = 0;
    private int mode = PolicyModel.DEFAULT;
    private String name;
    private String codebase;
    
    public Grant( String codebase )
    {
        this.name = "grant" + count++;
        this.codebase = codebase;
    }
    
    public Grant( String name, String codebase )
    {
        this.name = name;
        this.codebase = codebase;
    }
    

    public String getName()
    {
        return( name );
    }
    
    public String getCodebase()
    {
        return( codebase );
    }
    
    public Iterator getPermIterator()
    {
        return( myStorage.values().iterator() );
    }
    
    public void addPerm( Perm p )
    {
        myStorage.put( p.getName(), p );
    }
    
    public void deletePerm( Perm p )
    {
        myStorage.remove( p.getName() );
    }
    
    public boolean isMode( int m )
    {
        return( mode == m );
    }
    
    public void setMode( int m )
    {
        mode = m;
    }
    
    
    public Perm implies( Perm p )
    {
        Iterator i = getPermIterator();
        while ( i.hasNext() )
        {
            Perm perm = (Perm)i.next();
            if ( perm.implies( p ) ) return( perm );
        }
        return( null );
    }
    

    public String toString()
    {
        return( name + "-" + codebase );
    }
    
    
    
}
