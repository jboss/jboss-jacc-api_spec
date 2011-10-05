/*
 * JBoss, Home of Professional Open Source
 * Copyright 2005, JBoss Inc., and individual contributors as indicated
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package javax.security.jacc;

import java.io.Serializable;
import java.security.Permission;

/**
 * Class for EJB isCallerInRole (String reference) permissions. An EJBRoleRefPermission is a named permission and has actions.
 * 
 * The name of an EJBRoleRefPermission contains the value of the ejb-name element in the application's deployment descriptor
 * that identifies the EJB in whose context the permission is being evalutated.
 * 
 * The actions of an EJBRoleRefPermission identifies the role reference to which the permission applies. An EJBRoleRefPermission
 * is checked to determine if the subject is a member of the role identified by the reference.
 * 
 * Implementations of this class MAY implement newPermissionCollection or inherit its implementation from the super class.
 * 
 * @author Scott.Stark@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public final class EJBRoleRefPermission extends Permission implements Serializable {
    /** @since 4.0.2 */
    private static final long serialVersionUID = 1;

    /** The security-role-ref/role-link value */
    private String actions;
    private transient int hashCode;

    /**
     * Creates a new EJBRoleRefPermission with the specified name and actions.
     * 
     * @param ejbName - the ejb-name that identifies the EJB in whose context the role references are to be evaluated.
     * @param actions - identifies the role reference to which the permission pertains. The role reference is scoped to the EJB
     *        identified in the name parameter. The value of the role reference must not be null or the empty string.
     */
    public EJBRoleRefPermission(String ejbName, String actions) {
        super(ejbName);
        this.actions = actions;
        this.hashCode = ejbName.hashCode() + actions.hashCode();
    }

    /**
     * Test an EJBRoleRefPermission for equality.
     * 
     * @param p
     * @return
     */
    public boolean equals(Object p) {
        if (p == this)
            return true;
        if ((p instanceof EJBRoleRefPermission) == false)
            return false;

        boolean equals = false;
        EJBRoleRefPermission errp = (EJBRoleRefPermission) p;
        String pname = errp.getName();
        if (this.getName().equals(pname)) {
            String pactions = errp.getActions();
            if (this.getActions().equals(pactions))
                equals = true;
        }
        return equals;
    }

    public String getActions() {
        return actions;
    }

    public int hashCode() {
        return hashCode;
    }

    /**
     * Determines if the argument Permission is "implied by" this EJBRoleRefPermission. For this to be the case,
     * 
     * - The argument must be an instanceof EJBRoleRefPermission - with name equivalent to that of this EJBRoleRefPermission,
     * and - with the role reference equivalent to that of this EJBRoleRefPermission applies.
     * 
     * The name and actions comparisons described above are case sensitive.
     * 
     * @param p - the EJBRoleRefPermission to test
     * @return true if the specified permission is implied by this object, false otherwise.
     */
    public boolean implies(Permission p) {
        return equals(p);
    }

    /**
     * Returns a string describing this Permission.
     */
    public String toString() {
        return "[" + getName() + ",role-ref=" + actions + "]";
    }
}
