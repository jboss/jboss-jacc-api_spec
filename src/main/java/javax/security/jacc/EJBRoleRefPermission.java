package javax.security.jacc;

import java.io.Serializable;
import java.security.Permission;

/**
 * <p>
 * Class for EJB <i>isCallerInRole (String reference)</i> permissions. An EJBRoleRefPermission is a named permission and
 * has actions.
 * </p>
 * 
 * <p>
 * The name of an EJBRoleRefPermission contains the value of the ejb-name element in the application's deployment
 * descriptor that identifies the EJB in whose context the permission is being evaluated.
 * </p>
 * 
 * <p>
 * The actions of an EJBRoleRefPermission identifies the role reference to which the permission applies. An
 * EJBRoleRefPermission is checked to determine if the subject is a member of the role identified by the reference.
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
public final class EJBRoleRefPermission extends Permission implements Serializable
{
   private static final long serialVersionUID = 1;

   /** The security-role-ref/role-link value */
   private String actions;

   private transient int hashCode;

   /**
    * <p>
    * Creates a new EJBRoleRefPermission with the specified name and actions.
    * </p>
    * 
    * @param ejbName
    *           - the ejb-name that identifies the EJB in whose context the role references are to be evaluated.
    * @param actions
    *           - identifies the role reference to which the permission pertains. The role reference is scoped to the
    *           EJB identified in the name parameter. The value of the role reference must not be {@code null} or the
    *           empty string.
    */
   public EJBRoleRefPermission(String ejbName, String actions)
   {
      super(ejbName);
      this.actions = actions;
      this.hashCode = ejbName.hashCode() + actions.hashCode();
   }

   /**
    * <p>
    * Checks two EJBRoleRefPermission objects for equality. EJBRoleRefPermission objects are equivalent if they have
    * case equivalent name and actions values.
    * </p>
    * 
    * <p>
    * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) && P2.implies(P1).
    * </p>
    * 
    * @param o
    *           - the EJBRoleRefPermission object being tested for equality with this EJBRoleRefPermission.
    * @return true if the argument EJBRoleRefPermission object is equivalent to this EJBRoleRefPermission.
    */
   @Override
   public boolean equals(Object o)
   {
      if ((o instanceof EJBRoleRefPermission) == false)
         return false;

      boolean equals = false;
      EJBRoleRefPermission errp = (EJBRoleRefPermission) o;
      String pname = errp.getName();
      if (this.getName().equals(pname))
      {
         String pactions = errp.getActions();
         if (this.getActions().equals(pactions))
            equals = true;
      }
      return equals;
   }

   /**
    * <p>
    * Returns a canonical String representation of the actions of this EJBRoleRefPermission.
    * </p>
    * 
    * @return a String containing the canonicalized actions of this EJBRoleRefPermission.
    */
   @Override
   public String getActions()
   {
      return actions;
   }

   /**
    * <p>
    * Returns the hash code value for this EJBRoleRefPermission. The properties of the returned hash code must be as
    * follows:
    * <ul>
    * <li>During the lifetime of a Java application, the hashCode method must return the same integer value, every time
    * it is called on a EJBRoleRefPermission object. The value returned by hashCode for a particular
    * EJBRoleRefPermission need not remain consistent from one execution of an application to another.</li>
    * <li>If two EJBRoleRefPermission objects are equal according to the equals method, then calling the hash- Code
    * method on each of the two Permission objects must produce the same integer result (within an application).</li>
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
    * Determines if the argument Permission is "implied by" this EJBRoleRefPermission. For this to be the case,
    * <ul>
    * <li>The argument must be an instance of EJBRoleRefPermission with name equivalent to that of this
    * EJBRoleRefPermission, and with the role reference equivalent to that of this EJBRoleRefPermission applies.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * The name and actions comparisons described above are case sensitive.
    * </p>
    * 
    * @param permission
    *           - “this” EJBRoleRefPermission is checked to see if it implies the argument permission.
    * @return true if the specified permission is implied by this object, false if not.
    */
   public boolean implies(Permission permission)
   {
      return equals(permission);
   }

   /**
    * <p>
    * Returns the {@code String} representation of this permission, which has the following form:
    * 
    * <pre>
    * [ejb-name,role-ref=actions]
    * </pre>
    * 
    * </p>
    */
   public String toString()
   {
      return "[" + getName() + ",role-ref=" + actions + "]";
   }
}
