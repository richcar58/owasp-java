package org.owasp.java.policysnoop;

import java.awt.*; 
import java.awt.event.*; 
import java.util.*;

import javax.swing.*; 
import javax.swing.event.*; 
import javax.swing.tree.*; 
import javax.accessibility.*; 
  
  
public class PermPanel extends JPanel
{
    JLabel name = new JLabel();
    
    public PermPanel()
    {
        this.setLayout( new BorderLayout() );
        this.add( name, BorderLayout.CENTER );
    }
    
    public void update( Perm p )
    {
        name.setText( p.getType() );
    }
    
}