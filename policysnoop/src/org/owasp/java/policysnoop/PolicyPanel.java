
package org.owasp.java.policysnoop;

import java.awt.*; 
import java.awt.event.*; 
import java.util.*;

import javax.swing.*; 
import javax.swing.event.*; 
import javax.swing.tree.*; 
import javax.accessibility.*; 
  
  
public class PolicyPanel extends JPanel
{
    JLabel name = new JLabel();
    
    public PolicyPanel()
    {
        this.setLayout( new BorderLayout() );
        this.add( name, BorderLayout.CENTER );
    }
    
    public void update( PolicyModel p )
    {
        name.setText( "Policy" );
    }
    
}