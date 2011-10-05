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
 * Class for Servlet isUserInRole (String reference) permissions. A WebRoleRefPermission is a named permission and has actions.
 * 
 * The name of an WebRoleRefPermission (also referred to as the target name) identifies a Web resource by the servlet name (in
 * the deployment descriptor corresponding to the component from which the call to isUserInRole (String reference) is being
 * made.
 * 
 * The actions of an WebRoleRefPermission identifies the role reference to which the permission applies. A WebRoleRefPermission
 * is checked to determine if the subject is a member of the role identified by the reference.
 * 
 * Implementations of this class MAY implement newPermissionCollection or inherit its implementation from the super class.
 * 
 * @link http://java.sun.com/j2ee/1.4/docs/api/
 * 
 * @author Scott.Stark@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public final class WebRoleRefPermission extends Permission implements Serializable {
    /** @since 4.0.2 */
    private static final long serialVersionUID = 1;

    /** The security-role-ref/role-link value */
    private String actions;
    private transient int hashCode;

    /**
     * Creates a new WebRoleRefPermission with the specified name and actions.
     * 
     * @param name - the servlet-name that identifies the application specific web resource in whose context the role references
     *        are to be evaluated.
     * @param actions - identifies the role reference to which the permission pertains. The role reference is scoped to the Web
     *        resource identified in the name parameter. The value of the role reference must not be null or the empty string.
     */
    public WebRoleRefPermission(String name, String actions) {
        super(name);
        this.actions = actions;
        this.hashCode = name.hashCode() + actions.hashCode();
    }

    /**
     * Checks two WebRoleRefPermission objects for equality. WebRoleRefPermission objects are equivalent if they have case
     * equivalent name and actions values.
     * 
     * @param p the permission to check for equality
     * @return true if this is equivalent to p, false otherwise.
     */
    public boolean equals(Object p) {
        if (p == this)
            return true;
        if ((p instanceof WebRoleRefPermission) == false)
            return false;

        boolean equals = false;
        WebRoleRefPermission wrrp = (WebRoleRefPermission) p;
        String pname = wrrp.getName();
        if (this.getName().equals(pname)) {
            String pactions = wrrp.getActions();
            if (this.getActions().equals(pactions))
                equals = true;
        }
        return equals;
    }

    /**
     * Returns the security-role-ref target role name.
     * 
     * @return the security-role-ref target role name.
     */
    public String getActions() {
        return actions;
    }

    /**
     * Returns the hash code value for this WebRoleRefPermission. The properties of the returned hash code must be as follows:
     * 
     * - During the lifetime of a Java application, the hashCode method must return the same integer value, every time it is
     * called on a WebRoleRefPermission object. The value returned by hashCode for a particular WebRoleRefPermission need not
     * remain consistent from one execution of an application to another. - If two WebRoleRefPermission objects are equal
     * according to the equals method, then calling the hashCode method on each of the two Permission objects must produce the
     * same integer result (within an application).
     * 
     * @return the permission hash code.
     */
    public int hashCode() {
        return hashCode;
    }

    /**
     * Determines if the argument Permission is "implied by" this WebRoleRefPermission. For this to be the case:
     * 
     * - The argument must be an instanceof WebRoleRefPermission - with name equivalent to this WebRoleRefPermission, and - with
     * role reference equivalent to this WebRoleRefPermission (as defined in their actions)
     * 
     * @param p
     * @return true if the specified permission is implied by this object, false otherwise.
     */
    public boolean implies(Permission p) {
        return equals(p);
    }
}
