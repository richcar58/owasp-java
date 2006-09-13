
package org.owasp.java.policysnoop;

import java.awt.*; 
import java.awt.event.*; 
import java.io.*;
import java.net.URL;
import java.util.*;

import javax.swing.*; 
import javax.swing.event.*; 
import javax.swing.tree.*; 
import javax.swing.filechooser.*;
import javax.accessibility.*; 
  
  
public class PolicyGUI implements PolicyListener
{
    private JFrame frame;
    private DefaultMutableTreeNode root = new DefaultMutableTreeNode( "Policy", true );
    private DefaultTreeModel tree = new DefaultTreeModel( root );
    
    private PermPanel permPanel = new PermPanel();
    private GrantPanel grantPanel = new GrantPanel();
    private PolicyPanel policyPanel = new PolicyPanel();
    private JSplitPane splitPane;
    private JTree jtree;

    private Hashtable commands;
    private Hashtable menuItems;
    private JMenuBar menubar;
    private JToolBar toolbar;
    protected FileDialog fileDialog;

    
    private PolicyModel pm;
    
    public PolicyGUI( PolicyModel pm )
    {
        this.pm = pm;
        
	    menubar = createMenubar();
		frame = createFrame( "PolicySnoop" );
	    frame.getContentPane().add( "North", createMenubar() );
    	frame.getContentPane().add( "Center", createContent() );
    	frame.toFront();
    	frame.setVisible(true);
    }

    protected JMenuBar createMenubar()
    {
        // install the command table
        commands = new Hashtable();
        Action[] actions = getActions();
        for (int i = 0; i < actions.length; i++)
        {
            Action a = actions[i];
            commands.put(a.getValue(Action.NAME), a);
        }
        
	    menuItems = new Hashtable();
	    JMenuItem mi;
	    JMenuBar mb = new JMenuBar();

    	JMenu menu = new JMenu( "File" );
		menu.add( createMenuItem( openAction ) );
        menu.add( createMenuItem( saveAction ) );
        menu.add( createMenuItem( runAction ) );
        menu.add( createMenuItem( learnAction ) );
        menu.add( createMenuItem( askAction ) );
        menu.addSeparator();
        menu.add( createMenuItem( exitAction ) );
		mb.add( menu );
		
	    return mb;
    }

    protected JMenuItem createMenuItem( String cmd )
    {
	    JMenuItem mi = new JMenuItem( cmd );
	    // mi.setHorizontalTextPosition(JButton.RIGHT);
	    // mi.setIcon(new ImageIcon(url));
	    mi.setActionCommand( cmd );
	    Action a = getAction( cmd );
	    if (a != null) {
	        mi.addActionListener(a);
	        mi.setEnabled(a.isEnabled());
	    } else {
	        mi.setEnabled(false);
	    }
	    menuItems.put(cmd, mi);
	    return mi;
    }

    
    public JComponent createContent()
    {
        jtree = createTree();
        jtree.getSelectionModel().setSelectionMode( TreeSelectionModel.SINGLE_TREE_SELECTION );

        //Listen for when the selection changes.
        jtree.addTreeSelectionListener(new TreeSelectionListener()
        {
            public void valueChanged(TreeSelectionEvent e)
            {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode)jtree.getLastSelectedPathComponent();
                if (node == null) return;

                Object o = node.getUserObject();
                if ( o instanceof Perm )
                {
                    permPanel.update( (Perm)o );
                    splitPane.setRightComponent( permPanel );
                }
                else if ( o instanceof Grant )
                {
                    grantPanel.update( (Grant)o );
                    splitPane.setRightComponent( grantPanel );
                }
                else if ( o instanceof PolicyModel )
                {
                    policyPanel.update( (PolicyModel)o );
                    splitPane.setRightComponent( policyPanel );
                }
            }
        });

        JComponent scrollTree = new JScrollPane( jtree );
                
        splitPane = new JSplitPane( JSplitPane.HORIZONTAL_SPLIT, scrollTree, permPanel ); 
        splitPane.setContinuousLayout( true ); 
        splitPane.setOneTouchExpandable( true );
        splitPane.setDividerLocation( 500 );

        JPanel mainPanel = new JPanel( new BorderLayout() );
        mainPanel.add( splitPane, BorderLayout.CENTER );
        return( mainPanel );
	}

    
    public JTree createTree()
    {
        Iterator gi = pm.getGrantIterator();
        while ( gi.hasNext() )
        {
            Grant g = (Grant)gi.next();
            this.grantAdded( g );
            
            Iterator pi = g.getPermIterator();
            while ( pi.hasNext() )
            {
                Perm p = (Perm)pi.next();
                this.permAdded( g, p );
            }
        }
  
        JTree jtree = new JTree( tree )
        { 
            public Insets getInsets()
            { 
                return new Insets( 5,5,5,5 );
            } 
        }; 
        return( jtree );
    }
    
    
    private String unslash( String string )
    {
        StringBuffer sb = new StringBuffer();
        for ( int loop=0; loop<string.length(); loop++ )
        {
            char c = string.charAt( loop );
            if ( c == '\\' ) sb.append( c );  // insert an extra backslash for Windoze
            sb.append( c );
        }
        return( sb.toString() );
    }
    

	
	// creates a Frame with the appropriate title and centers it on the screen
	private static JFrame createFrame( String myTitle )
	{
		JFrame f = new JFrame( myTitle );

		// add a WindowListener to handle window close events
		f.addWindowListener
		(
			new WindowAdapter()
			{
				public void windowClosing( WindowEvent e )
				{
					// System.exit( 0 );
				}
			}
		);

		// calculate size and location
        Dimension screenDimension = Toolkit.getDefaultToolkit().getScreenSize();
        int width = (int)screenDimension.getWidth();
        int height = (int)screenDimension.getHeight();
        Dimension frameDimension = new Dimension( width-100, height-100 );
		f.setSize( frameDimension );
		f.setLocation( new Point( 100/2, 100/2 ) );
		return( f );
	}


    private String[] buttons = { "auto", "allow once", "add to policy", "generalize", "throw once", "throw always", "dump", "exit VM" };
    
    private int showDialog( String title, String message, Grant g, Perm p )
    {
        return( 
            JOptionPane.showOptionDialog(
                null,
                message,
                title,
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null,
                buttons,
                "allow once" )
            );
    }
    
    
/*
                String request = codeBase + " " + actions + " access to \"" + perm.getName() + "\"";
                String policy = formatPolicy( codeBase, perm );
                
	            String message = title + " request...\nDo you want to allow " + request + "?" + "\n\n" + policy;
                int button = showDialog( title, message );
                switch( button )
                {
                    case 0 : System.out.println( "\tSetting automatic mode" ); auto = true; break;
                    case 1 : System.out.println( "\tAllowing " + request + " one time" ); working = false; break;
                    case 2 : System.out.println( "\tAllowing " + request + " always" ); addPolicy( codeBase, perm ); working = false; break;
                    case 3 : System.out.println( "\tGeneralizing..." ); codeBase = generalize( codeBase ); perm = generalize( perm ); break;
                    case 4 : System.out.println( "\tThrowing exception in response to " + request ); throw new SecurityException( "User rejected " + request );
                    case 5 : System.out.println( "\tThrowing exception in response to " + request + " always" ); addPolicy( "__THROW" + codeBase, perm ); throw new SecurityException( "User rejected " + request );
                    // case 6 : System.out.println( "\tDumping policy" ); dumpPolicy(); showPolicy(); break;
                    // case 7 : System.out.println( "\tExiting VM in response to " + request ); dumpPolicy(); System.exit( -1 );
                    default : System.out.println( "Unknown button" ); working = false;
                }
            }
        }
    }


    private String[] generateOptions( String base, String delims, String[] mods )
    {
        Vector options = new Vector();
        try
        {
            // add the original to the list
            options.add( base );

            // generate and add options for each section of the base
            StringTokenizer st = new StringTokenizer( base, delims, true );
            String lead = "";
            while ( st.hasMoreTokens() )
            {
                String token = st.nextToken();
                String delim = "";
                if ( st.hasMoreTokens() )
                {
                    delim = st.nextToken();
                }
                if ( st.hasMoreTokens() )  // skip the last one since we added the full one above
                {
                    options.add( lead + token + delim );
                    for ( int loop=0; loop<mods.length; loop++ )
                    {
                        options.add( lead + token + delim + mods[loop] );
                    }
                    lead += token + delim;
                }
            }
        }
        catch( Exception e )
        {
            e.printStackTrace();
        }
        return( (String[])options.toArray( new String[1] ) );
    }

    private Permission generalize( Permission perm )
    {
        String[] options = null;
        
        String sep = "" + File.separatorChar;
        if ( perm instanceof FilePermission ) options = generateOptions( perm.getName(), sep, new String[] { "*", "-" } );   // FIXME -- could add "<<ALL FILES>>"
        if ( perm instanceof RuntimePermission ) options = generateOptions( perm.getName(), ".", new String[] { "*" } );
        if ( perm instanceof PropertyPermission ) options = generateOptions( perm.getName(), ".", new String[] { "*" } );
        // FIXME: Sockets are hard
        // if ( perm instanceof SocketPermission ) options = generateOptions( perm.getName(), ".", new String[] { "*" } );
        
        String name = JOptionPane.showInputDialog
            (
                null,
                "Please generalize permission name...",
                "Permission Name Generalizer",
                JOptionPane.INFORMATION_MESSAGE,
                null,
                options,
                perm.getName()
            ).toString();
         
        String actions = JOptionPane.showInputDialog
            (
                null,
                "Please generalize permission actions...",
                "Permission Action Generalizer",
                JOptionPane.INFORMATION_MESSAGE,
                null,
                null,
                perm.getActions()
            ).toString();
         
        // use reflection to copy the permission
        Permission gen = null;
        Constructor[] constructors = perm.getClass().getConstructors();
        Constructor constructor = null;

        try
        {
            // two arg constructor
            constructor = perm.getClass().getConstructor( new Class[] { String.class, String.class } );
            gen = (Permission)constructor.newInstance( new Object[] { name, actions } );
        }
        catch( Exception e1 )
        {
            try
            {
                // one arg constructor
                constructor = perm.getClass().getConstructor( new Class[] { String.class } );
                gen = (Permission)constructor.newInstance( new Object[] { name } );
            }
            catch( Exception e2 )
            {
                System.out.println( "Couldn't copy permission " + perm );
                System.out.println( "==> " + e1.getMessage() );
                System.out.println( "--> " + e2.getMessage() );
                for ( int loop=0; loop < constructors.length; loop++ )
                {
                    System.out.println( "    + " + constructors[loop] );
                }
            }
        }
        return( gen );
    }


    private String generalize( String codeBase )
    {
        String[] options = generateOptions( codeBase, "/", new String[] { "*", "-" } );
        
        String base = JOptionPane.showInputDialog
            (
                null,
                "Please generalize permission codeBase...",
                "Permission CodeBase Generalizer",
                JOptionPane.INFORMATION_MESSAGE,
                null,
                options,
                codeBase
            ).toString();
         
        return( base );
    }
*/




//*******************************************************************
// IMPLEMENT POLICYLISTENER
//*******************************************************************

    public void grantAdded( Grant g )
    {
        // add new grant node to tree
        DefaultMutableTreeNode grant = new DefaultMutableTreeNode( g, true );
        root.add( grant );
        int[] index = { tree.getIndexOfChild( root, grant ) };
        tree.nodesWereInserted( grant, index );
    }
    
    public void grantChanged( Grant g )
    {
        // update grant node in tree
        DefaultMutableTreeNode grant = findGrantNode( g );
        grant.setUserObject( g );
        tree.nodeChanged( grant );
    }
    
    public void grantDeleted( Grant g )
    {
        // remove grant node from tree
        DefaultMutableTreeNode grant = findGrantNode( g );
        grant.removeFromParent();
        int[] index = { tree.getIndexOfChild( root, grant ) };
        Object[] object = { g };
        tree.nodesWereRemoved( root, index, object );
    }
    

    public void permAdded( Grant g, Perm p )
    {
        // add new perm node to grant node
        DefaultMutableTreeNode grant = findGrantNode( g );
        if ( grant == null )
        {
            grantAdded( g );
            grant = findGrantNode( g );
        }
        DefaultMutableTreeNode perm = new DefaultMutableTreeNode( p, false );
        grant.add( perm );
        int[] index = { tree.getIndexOfChild( grant, perm ) };
        tree.nodesWereInserted( grant, index );
    }
    
    public void permChanged( Grant g, Perm p )
    {
        // update perm node in grant node
        DefaultMutableTreeNode perm = findPermNode( g, p );
        tree.nodeChanged( perm );
    }
    
    public void permDeleted( Grant g, Perm p )
    {
        // remove perm node from grant node
        DefaultMutableTreeNode grant = findGrantNode( g );
        DefaultMutableTreeNode perm = findPermNode( g, p );
        perm.removeFromParent();
        int[] index = { tree.getIndexOfChild( grant, perm ) };
        Object[] object = { p };
        tree.nodesWereRemoved( grant, index, object );
    }
    
    public void permRequested( Grant g, Perm p )
    {
        // display a dialog box and modify p;
        int button = showDialog( "Security Intercept", "FIXME", g, p );
        
        String request = g.toString() + "--->" + p.toString();
        switch( button )
        {
            case 0 : System.out.println( "\tSetting automatic mode" ); break;
            case 1 : System.out.println( "\tAllowing " + request + " one time" ); break;
            case 2 : System.out.println( "\tAllowing " + request + " always" ); permAdded( g, p ); break;
            case 3 : System.out.println( "\tGeneralizing..." ); break; // generalize codebase and target
            case 4 : System.out.println( "\tThrowing exception in response to " + request ); throw new SecurityException( "User rejected " + request );
            case 5 : System.out.println( "\tThrowing exception in response to " + request + " always" ); throw new SecurityException( "User rejected " + request );
            case 6 : System.out.println( "\tDumping policy" ); break;
            case 7 : System.out.println( "\tExiting VM in response to " + "FIXME" ); System.exit( 0 );
            default : System.out.println( "Unknown button" );
        }
        
        
    }

    
    
    
    private DefaultMutableTreeNode findGrantNode( Grant g )
    {
        Enumeration e = root.children();
        while( e.hasMoreElements() )
        {
            DefaultMutableTreeNode grant = (DefaultMutableTreeNode)e.nextElement();
            if ( grant.getUserObject() == g ) return( grant );
        }
        return( null );
    }
    
    private DefaultMutableTreeNode findPermNode( Grant g, Perm p )
    {
        DefaultMutableTreeNode grant = findGrantNode( g );
        Enumeration e = grant.children();
        while( e.hasMoreElements() )
        {
            DefaultMutableTreeNode perm = (DefaultMutableTreeNode)e.nextElement();
            if ( perm.getUserObject() == p ) return( perm );
        }
        return( null );
    }
 
    
    
    
//**********************************************************
// action implementations
//**********************************************************

    public static final String openAction = "Open";
    public static final String saveAction = "Save";
    public static final String runAction = "Run";
    public static final String exitAction = "Exit";
    public static final String learnAction = "Learn";
    public static final String askAction = "Ask";
    
    /**
     * Actions defined by the Notepad class
     */
    private Action[] defaultActions =
    {
	    new OpenAction(),
	    new SaveAction(),
	    new RunAction(),
	    new ExitAction(),
	    new LearnAction(),
	    new AskAction()
    };

    protected Action getAction(String cmd)
    {
    	return (Action) commands.get(cmd);
    }

    class OpenAction extends AbstractAction
    {
	    OpenAction()
	    {
	        super(openAction);
	    }

        public void actionPerformed(ActionEvent e)
        {
	        if (fileDialog == null)
	        {
    		    fileDialog = new FileDialog(frame);
	        }
	        fileDialog.setMode(FileDialog.LOAD);
	        fileDialog.show();

	        String file = fileDialog.getFile();
	        if (file == null)
	        {
	    	    return;
	        }
	        String directory = fileDialog.getDirectory();
	        File f = new File(directory, file);
	        if (f.exists())
	        {
	            // FIXME: do something
		    }
		    else
		    {
		        // handle it
		    }
		    frame.setTitle(file);
		    Thread loader = new FileLoader(f, pm );
		    loader.start();
	    }
    }
    

    /**
     * Really lame implementation of an exit command
     */
    class ExitAction extends AbstractAction
    {
	    ExitAction()
	    {
	        super(exitAction);
	    }

        public void actionPerformed(ActionEvent e)
        {
	        System.exit(0);
	    }
    }

    class SaveAction extends AbstractAction
    {
	    SaveAction()
	    {
	        super(saveAction);
	    }

        public void actionPerformed(ActionEvent e)
        {
            System.out.println( "SAVEACTION" );
	    }
    }

    class RunAction extends AbstractAction
    {
	    RunAction()
	    {
	        super(runAction);
	    }

        public void actionPerformed(ActionEvent e)
        {
            JTextField info = new JTextField( "Jeff is great" );
            info.setSize( 200, 40 );
            
            javax.swing.filechooser.FileFilter filter = new javax.swing.filechooser.FileFilter()
            {
                public boolean accept(File f) { return( f.isDirectory() || f.getName().endsWith( ".class" ) ); }
                public String getDescription() { return "Java class files"; }
            };
            
            JFileChooser jfc = new JFileChooser( homedir );
            jfc.setFileFilter( filter );
            jfc.setAccessory( info );
            
            int returnVal = jfc.showOpenDialog( frame );
            if(returnVal != JFileChooser.APPROVE_OPTION) return;
            
            homedir = jfc.getSelectedFile().getParentFile();
            String filename = jfc.getSelectedFile().getName();
            String clazz = filename.substring( 0, filename.indexOf( "." ) );

            // FIXME:
            StringTokenizer st = new StringTokenizer( info.getText(), " \t" );
            String args[] = new String[ st.countTokens() ];
            for ( int loop = 0; loop < st.countTokens(); loop++ )
            {
                args[ loop ] = (String)st.nextElement();
            }
            
            // FIXME: this only works for trivial stuff
            String classpath = homedir.getPath();
            
    		Runner.run( clazz, args, classpath );
	    }
    }
    
    File homedir = new File( System.getProperty( "user.dir" ) );
    String args = "";
    
    class LearnAction extends AbstractAction
    {
	    LearnAction()
	    {
	        super(learnAction);
	    }

        public void actionPerformed(ActionEvent e)
        {
            System.out.println( "Setting LEARN mode" );
            pm.setMode( PolicyModel.LEARNING );
	    }
    }

    
    class AskAction extends AbstractAction
    {
	    AskAction()
	    {
	        super(askAction);
	    }

        public void actionPerformed(ActionEvent e)
        {
            System.out.println( "Setting ASK mode" );
            pm.setMode( PolicyModel.ASKING );
	    }
    }

    
    public Action[] getActions()
    {
        return( defaultActions );
    }



    /**
     * Thread to load a file into the text storage model
     */
    class FileLoader extends Thread
    {
	    PolicyModel pm;
	    File f;
	    
	    FileLoader(File f, PolicyModel pm)
	    {
	        setPriority(4);
	        this.f = f;
	        this.pm = pm;
	    }

        public void run()
        {
	        try
	        {
		        // try to start reading
		        Reader in = new FileReader(f);
		        char[] buff = new char[4096];
		        int nch;
		        while ((nch = in.read(buff, 0, buff.length)) != -1)
		        {
		            // FIXME -- do something with the line you read
		        }
	        }
	        catch (IOException e) {
		        System.err.println(e.toString());
	        }
	    }
	}


}