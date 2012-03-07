package javax.security.jacc;

import java.io.Serializable;
import java.security.Permission;

/**
 * <p>
 * Class for Servlet <i>isUserInRole (String reference)</i> permissions. A WebRoleRefPermission is a named permission
 * and has actions.
 * </p>
 * 
 * <p>
 * The name of an WebRoleRefPermission (also referred to as the target name) identifies a Web resource by the servlet
 * name (in the deployment descriptor corresponding to the component from which the call to <i>isUserInRole (String
 * reference)</i> is being made).
 * </p>
 * 
 * <p>
 * The actions of an WebRoleRefPermission identifies the role reference to which the permission applies. A
 * WebRoleRefPermission is checked to determine if the subject is a member of the role identified by the reference.
 * </p>
 * 
 * <p>
 * Implementations of this class MAY implement newPermissionCollection or inherit its implementation from the super
 * class.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link Permission}
 */
public final class WebRoleRefPermission extends Permission implements Serializable
{
   private static final long serialVersionUID = 1;

   /** The security-role-ref/role-link value */
   private String actions;

   private transient int hashCode;

   /**
    * <p>
    * Creates a new WebRoleRefPermission with the specified name and actions.
    * </p>
    * 
    * @param name
    *           - the servlet-name that identifies the application specific web resource in whose context the role
    *           references are to be evaluated.
    * @param actions
    *           - identifies the role reference to which the permission pertains. The role reference is scoped to the
    *           Web resource identified in the name parameter. The value of the role reference must not be null or the
    *           empty string.
    */
   public WebRoleRefPermission(String name, String actions)
   {
      super(name);
      this.actions = actions;
      this.hashCode = name.hashCode() + actions.hashCode();
   }

   /**
    * <p>
    * Checks two WebRoleRefPermission objects for equality. WebRoleRefPermission objects are equivalent if they have
    * case equivalent name and actions values.
    * </p>
    * 
    * <p>
    * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) && P2.implies(P1).
    * </p>
    * 
    * <p>
    * The name and actions comparisons described above are case sensitive.
    * </p>
    * 
    * @param p
    *           - the WebRoleRefPermission object being tested for equality with this WebRoleRefPermission.
    * @return true if the argument WebRoleRefPermission object is equivalent to this WebRoleRefPermission.
    */
   @Override
   public boolean equals(Object p)
   {
      if (p == this)
         return true;
      if ((p instanceof WebRoleRefPermission) == false)
         return false;

      boolean equals = false;
      WebRoleRefPermission wrrp = (WebRoleRefPermission) p;
      String pname = wrrp.getName();
      if (this.getName().equals(pname))
      {
         String pactions = wrrp.getActions();
         if (this.getActions().equals(pactions))
            equals = true;
      }
      return equals;
   }

   /**
    * <p>
    * Returns a canonical String representation of the actions of this WebRoleRefPermission.
    * </p>
    * 
    * @return a String containing the canonicalized actions of this WebRoleRefPermission.
    */
   @Override
   public String getActions()
   {
      return actions;
   }

   /**
    * <p>
    * Returns the hash code value for this WebRoleRefPermission. The properties of the returned hash code must be as
    * follows:
    * <ul>
    * <li>During the lifetime of a Java application, the hashCode method must return the same integer value, every time
    * it is called on a WebRoleRefPermission object. The value returned by hashCode for a particular
    * WebRoleRefPermission need not remain consistent from one execution of an application to another.</li>
    * <li>If two WebRoleRefPermission objects are equal according to the equals method, then calling the hashCode method
    * on each of the two Permission objects must produce the same integer result (within an application).</li>
    * </ul>
    * </p>
    * 
    * @return the integer hash code value for this object.
    */
   @Override
   public int hashCode()
   {
      return hashCode;
   }

   /**
    * <p>
    * Determines if the argument Permission is "implied by" this WebRoleRefPermission. For this to be the case:
    * <ul>
    * <li>The argument must be an instance of WebRoleRefPermission</li>
    * <li>with name equivalent to this WebRoleRefPermission, and</li>
    * <li>with role reference equivalent to this WebRoleRefPermission (as defined in their actions)</li>
    * </ul>
    * </p>
    * 
    * <p>
    * The comparisons described above are case sensitive.
    * </p>
    * 
    * @param p
    *           - “this” WebRoleRefPermission is checked to see if it implies the argument permission.
    * @return true if the specified permission is implied by this object, false if not.
    */
   @Override
   public boolean implies(Permission p)
   {
      return equals(p);
   }
}
