package org.owasp.java.policysnoop;


import java.security.*;
import java.util.*;

public class PolicyModel
{
    
    public static int DEFAULT = 0;
    public static int LEARNING = 1;
    public static int ASKING = 2;
    public static int DISABLED = 3;
    public static int ENABLED = 4;
    
    private HashMap myStorage = new HashMap();
    private int mode = PolicyModel.LEARNING;
    
    
    public PolicyModel()
    {
    }


    public boolean isMode( int m )
    {
        return( mode == m );
    }
    
    public int getMode()
    {
        return( mode );
    }
    
    public void setMode( int m )
    {
        mode = m;
    }
    


    public Iterator getGrantIterator()
    {
        return( myStorage.values().iterator() );
    }
    
    public Grant getGrant( String codebase )
    {
        return( (Grant)myStorage.get( codebase ) );
    }
    
    public void handle( Permission perm, String codebase )
    {
        try
        {
            // get an appropriate Grant for this request
            Grant g = getGrant( codebase );
            if ( g == null )
            {
                g = new Grant( codebase );
                this.addGrant( g );
            }

            Perm p = new Perm( g, perm );
            
            if ( g.isMode( DEFAULT ) ) g.setMode( this.getMode() );
            if ( p.isMode( DEFAULT ) ) p.setMode( this.getMode() );
            
            
            // is there an enabled permission that allows this action
            Perm allower = g.implies( p );
            if ( allower != null )
            {
                allower.use();
                this.modifyPerm( g, allower );
            }
            
            // is Grant in learn mode
            else if ( g.isMode( LEARNING ) )
            {
                this.addPerm( g, p );
            }
            
            // is Grant in ask mode
            else if ( g.isMode( ASKING ) )
            {
                this.requestPerm( g, p );
            }
            
            else throw new SecurityException( "No permission: " + p );
        }
        catch( Exception e )
        {
            System.out.println( "FIXME: why is this happening" );
            e.printStackTrace();
        }
    }
        

//*******************************************************************
// SUPPORT POLICYLISTENERS
//*******************************************************************
    
    private Vector listeners = new Vector();
    public void addPolicyListener( PolicyListener listener )
    {
        listeners.add( listener );
    }
    
    public void removePolicyListener( PolicyListener listener )
    {
        listeners.remove( listener );
    }
    
    public void addGrant( Grant g )
    {
        myStorage.put( g.getCodebase(), g );
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.grantAdded( g );
        }
    }
        
    public void deleteGrant( Grant g )
    {
        myStorage.remove( g.getCodebase() );
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.grantDeleted( g );
        }
    }
    
    public void modifyGrant( Grant g )
    {
        // FIXME??
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.grantChanged( g );
        }
    }

    public void setGrant( Grant g, int mode )
    {
        g.setMode( mode );
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.grantChanged( g );
        }
    }

    
    public void addPerm( Grant g, Perm p )
    {
        g.addPerm( p );
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.permAdded( g, p );
        }
    }
        
    public void deletePerm( Grant g, Perm p )
    {
        g.deletePerm( p );
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.permDeleted( g, p );
        }
    }
    
    public void modifyPerm( Grant g, Perm p )
    {
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.permChanged( g, p );
        }
    }
    
    public void requestPerm( Grant g, Perm p )
    {
        g.addPerm( p );
        Iterator i = listeners.iterator();
        while ( i.hasNext() )
        {
            PolicyListener listener = (PolicyListener)i.next();
            listener.permRequested( g, p );
        }
    }
        
}
