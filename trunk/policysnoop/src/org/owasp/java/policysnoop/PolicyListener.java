package org.owasp.java.policysnoop;

public interface PolicyListener
{
    public void grantAdded( Grant g );
    public void grantChanged( Grant g );
    public void grantDeleted( Grant g );

    public void permAdded( Grant g, Perm p );
    public void permChanged( Grant g, Perm p );
    public void permDeleted( Grant g, Perm p );
    public void permRequested( Grant g, Perm p );
}