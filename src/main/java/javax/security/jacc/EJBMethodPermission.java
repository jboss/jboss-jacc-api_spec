package javax.security.jacc;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * <p>
 * Class for EJB method permissions.
 * </p>
 * 
 * <p>
 * The name of an EJBMethodPermission contains the value of the ejb-name element in the application’s deployment
 * descriptor that identifies the target EJB.
 * </p>
 * 
 * <p>
 * The actions of an EJBMethodPermission identifies the methods of the EJB to which the permission applies.
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
public final class EJBMethodPermission extends Permission implements Serializable
{
   private static final long serialVersionUID = 1;

   /**
    * @serialField actions String the actions string.
    */
   private static final ObjectStreamField[] serialPersistentFields = {new ObjectStreamField("actions", String.class)};

   private transient String methodName;

   private transient String methodInterface;

   private transient String methodSig;

   /**
    * <p>
    * Creates a new EJBMethodPermission with the specified name and actions.
    * </p>
    * 
    * <p>
    * The name contains the value of the ejb-name element corresponding to an EJB in the application's deployment
    * descriptor.
    * </p>
    * 
    * <p>
    * The actions contains a methodSpec. The syntax of the actions parameter is defined as follows:
    * </p>
    * 
    * <pre>
    * methodNameSpec ::= methodName | emptyString
    * 
    * methodInterfaceName ::= String
    * 
    * methodInterfaceSpec ::= methodInterfaceName | emptyString
    * 
    * typeName ::= typeName | typeName []
    * 
    * methodParams ::= typeName | methodParams comma typeName
    * 
    * methodParamsSpec ::= emptyString | methodParams
    * 
    * methodSpec ::= null | methodNameSpec | methodNameSpec comma
    * methodInterfaceName | methodNameSpec comma methodInterfaceSpec comma
    * methodParamsSpec
    * </pre>
    * 
    * <p>
    * A MethodInterfaceName is a non-empty String and should contain a method-intf value as defined for use in EJB
    * deployment descriptors. An implementation must be flexible such that it supports additional interface names
    * especially if they are standardized by the EJB Specification. The EJB Specification currently defines the
    * following method-intf values:
    * </p>
    * 
    * <pre>
    * 
    * {&quot;Home&quot;, &quot;LocalHome&quot;, &quot;Remote&quot;, &quot;Local&quot;, &quot;ServiceEndpoint&quot;}
    * </pre>
    * 
    * <p>
    * A null or empty string methodSpec indicates that the permission applies to all methods of the EJB. A methodSpec
    * with a methodNameSpec of the empty string matches all methods of the EJB that match the methodInterface and
    * methodParams elements of the methodSpec.
    * </p>
    * 
    * <p>
    * A methodSpec with a methodInterfaceSpec of the empty string matches all methods of the EJB that match the
    * methodNameSpec and methodParamsSpec elements of the methodSpec.
    * </p>
    * 
    * <p>
    * A methodSpec without a methodParamsSpec matches all methods of the EJB that match the methodNameSpec and
    * methodInterface elements of the methodSpec.
    * </p>
    * 
    * <p>
    * The order of the typeNames in methodParams array must match the order of occurrence of the corresponding
    * parameters in the method signature of the target method(s). Each typeName in the methodParams must contain the
    * canonical form of the corresponding parameter's typeName as defined by the getActions method. A methodSpec with an
    * empty methodParamsSpec matches all 0 argument methods of the EJB that match the methodNameSpec and
    * methodInterfaceSpec elements of the methodSpec.
    * </p>
    * 
    * @param name
    *           - the ejb-name to which the permission pertains.
    * @param actions
    *           - identifies the methods of the EJB to which the permission pertains.
    */
   public EJBMethodPermission(String name, String actions)
   {
      super(name);
      parseMethodSpec(actions);
   }

   /**
    * <p>
    * Creates a new EJBMethodPermission with name corresponding to the EJBName and actions composed from
    * methodInterface, and the Method object.
    * </p>
    * 
    * <p>
    * A container uses this constructor prior to checking if a caller has permission to call the method of an EJB.
    * </p>
    * 
    * @param ejbName
    *           - The string representation of the name of the EJB as it appears in the corresponding ejb-name element
    *           in the deployment descriptor.
    * @param methodInterface
    *           - A string that may be used to specify the EJB interface to which the permission pertains. A value of
    *           null or "", indicates that the permission pertains to all methods that match the other parameters of the
    *           permission specification without consideration of the interface they occur on.
    * @param method
    *           - an instance of the Java.lang.reflect.Method class corresponding to the method that the container is
    *           trying to determine whether the caller has permission to access. This value must not be null.
    */
   public EJBMethodPermission(String ejbName, String methodInterface, Method method)
   {
      this(ejbName, method.getName(), methodInterface, convertParameters(method.getParameterTypes()));
   }

   /**
    * <p>
    * Creates a new EJBMethodPermission with name corresponding to the EJBName and actions composed from methodName,
    * methodInterface, and methodParams.
    * </p>
    * 
    * @param ejbName
    *           - The string representation of the name of the EJB as it appears in the corresponding ejb-name element
    *           in the deployment descriptor.
    * @param methodName
    *           - A string that may be used to indicate the method of the EJB to which the permission pertains. A value
    *           of null or "" indicates that the permission pertains to all methods that match the other parameters of
    *           the permission specification without consideration of method name.
    * @param methodInterface
    *           - A string that may be used to specify the EJB interface to which the permission pertains. A value of
    *           null or "", indicates that the permission pertains to all methods that match the other parameters of the
    *           permission specification without consideration of the interface they occur on.
    * @param methodParams
    *           - An array of strings that may be used to specify (by typeNames) the parameter signature of the target
    *           methods. The order of the typeNames in methodParams array must match the order of occurrence of the
    *           corresponding parameters in the method signature of the target method(s). Each typeName in the
    *           methodParams array must contain the canonical form of the corresponding parameter's typeName as defined
    *           by the getActions method. An empty methodParams array is used to represent a method signature with no
    *           arguments. A value of null indicates that the permission pertains to all methods that match the other
    *           parameters of the permission specification without consideration of method signature.
    */
   public EJBMethodPermission(String ejbName, String methodName, String methodInterface, String[] methodParams)
   {
      super(ejbName);
      this.methodInterface = methodInterface;
      this.methodName = methodName;
      if (methodParams == null)
         methodSig = null;
      else
      {
         StringBuffer tmp = new StringBuffer();
         for (String methodParam : methodParams)
         {
            tmp.append(methodParam);
            tmp.append(',');
         }
         if (tmp.length() > 0)
            tmp.setLength(tmp.length() - 1);
         methodSig = tmp.toString();
      }
   }

   /**
    * <p>
    * Checks two EJBMethodPermission objects for equality. EJBMethodPermission objects are equivalent if they have case
    * sensitive equivalent name and actions values.
    * </p>
    * 
    * <p>
    * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) && P2.implies(P1).
    * </p>
    * 
    * @param o
    *           - The EJBMethodPermission object being tested for equality with this EJBMethodPermission
    * @return true if the argument EJBMethodPermission object is equivalent to this EJBMethodPermission.
    */
   @Override
   public boolean equals(Object o)
   {
      boolean equals = false;
      if (o == null || !(o instanceof EJBMethodPermission))
         return false;
      EJBMethodPermission perm = (EJBMethodPermission) o;
      equals = getName().equals(perm.getName());
      if (equals == true)
      {
         // Check the method names
         if (methodName != null)
         {
            if (perm.methodName == null)
               return false;
            if (methodName.equals(perm.methodName) == false)
               return false;
         }
         else if (perm.methodName != null)
         {
            return false;
         }

         // Check the method interfaces
         equals = methodInterface != perm.methodInterface;
         if (equals == false && methodInterface != null)
            equals = methodInterface.equals(perm.methodInterface);
         if (equals == false)
            return false;

         // Check the method parameters
         if (methodSig != null)
         {
            equals = perm.methodSig != null && methodSig.equals(perm.methodSig);
         }
         else
         {
            equals = perm.methodSig == null;
         }
      }
      return equals;
   }

   /**
    * <p>
    * Returns the hash code value for this EJBMethodPermission. The properties of the returned hash code must be as
    * follows:
    * <ul>
    * <li>During the lifetime of a Java application, the hashCode method must return the same integer value every time
    * it is called on a EJBMethodPermission object. The value returned by hashCode for a particular EJBMethodPermission
    * need not remain consistent from one execution of an application to another.</li>
    * <li>If two EJBMethodPermission objects are equal according to the equals method, then calling the hash- Code
    * method on each of the two Permission objects must produce the same integer result (within an application).</li>
    * </ul>
    * </p>
    * 
    * @return the integer hash code value for this object.
    */
   @Override
   public int hashCode()
   {
      int hashCode = 0;
      if (methodName != null)
         hashCode += methodName.hashCode();
      if (methodInterface != null)
         hashCode += methodInterface.hashCode();
      if (methodSig != null)
         hashCode += methodSig.hashCode();
      return hashCode;
   }

   /**
    * <p>
    * Returns a String containing a canonical representation of the actions of this EJBMethodPermission. The Canonical
    * form of the actions of an EJBMethodPermission is described by the following syntax description.
    * </p>
    * 
    * <pre>
    * methodNameSpec ::= methodName | emptyString
    * 
    * methodInterfaceName ::= String
    * 
    * methodInterfaceSpec ::= methodInterfaceName | emptyString
    * 
    * typeName ::= typeName | typeName []
    * 
    * methodParams ::= typeName | methodParams comma typeName
    * 
    * methodParamsSpec ::= emptyString | methodParams
    * 
    * methodSpec ::= null |
    *      methodName |
    *      methodNameSpec comma methodInterfaceName |
    *      methodNameSpec comma methodInterfaceSpec comma methodParamsSpec
    * </pre>
    * 
    * <p>
    * The canonical form of each typeName must begin with the fully qualified Java name of the corresponding parameter's
    * type. The canonical form of a typeName for an array parameter is the fully qualified Java name of the array's
    * component type followed by as many instances of the string "[]" as there are dimensions to the array. No
    * additional characters (e.g. blanks) may occur in the canonical form.
    * </p>
    * 
    * <p>
    * A MethodInterfaceName is a non-empty String and should contain a method-intf value as defined for use in EJB
    * deployment descriptors. An implementation must be flexible such p it supports additional interface names
    * especially if they are standardized by the EJB Specification. The EJB Specification currently defines the
    * following method-intf values: { "Home", "LocalHome", "Remote", "Local", "ServiceEndpoint" }
    * </p>
    * 
    * @return a String containing the canonicalized actions of this EJBMethodPermission.
    */
   @Override
   public String getActions()
   {
      StringBuffer actions = new StringBuffer();
      if (methodName != null)
         actions.append(methodName);
      if (methodInterface != null)
      {
         actions.append(',');
         actions.append(methodInterface);
      }
      else if (methodSig != null)
      {
         actions.append(',');
      }

      if (methodSig != null)
      {
         actions.append(',');
         actions.append(methodSig);
      }
      String methodSpec = null;
      if (actions.length() > 0)
         methodSpec = actions.toString();
      return methodSpec;
   }

   /**
    * <p>
    * Determines if the argument Permission is "implied by" this EJBMethodPermission. For this to be the case,
    * <ul>
    * <li>The argument must be an instance of EJBMethodPermission</li>
    * <li>with name equivalent to that of this EJBMethodPermission, and</li>
    * <li>the methods to which the argument permission applies (as defined in its actions) must be a subset of the
    * methods to which this EJBMethodPermission applies (as defined in its actions).</li>
    * </ul>
    * </p>
    * 
    * <p>
    * The argument permission applies to a subset of the methods to which this permission applies if all of the
    * following conditions are met:
    * <ul>
    * <li>the method name component of the methodNameSpec of this permission is null, the empty string, or equivalent to
    * the method name of the argument permission, and</li>
    * <li>the method interface component of the methodNameSpec of this permission is null, the empty string, or
    * equivalent to the method interface of the argument permission, and</li>
    * <li>the method parameter list component of the methodNameSpec of this permission is null, the empty string, or
    * equivalent to the method parameter list of the argument permission.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * The name and actions comparisons described above are case sensitive.
    * </p>
    * 
    * @param permission
    *           - “this” EJBMethodPermission is checked to see if it implies the argument permission.
    * @return true if the specified permission is implied by this object, false if not.
    */
   @Override
   public boolean implies(Permission permission)
   {
      boolean implies = false;
      if (permission instanceof EJBMethodPermission == false)
         return false;
      EJBMethodPermission perm = (EJBMethodPermission) permission;
      implies = getName().equals(perm.getName());
      if (implies == false)
         return false;

      // See if permission is a subset of the method names
      if (methodName != null)
      {
         implies = methodName.equals(perm.methodName);
      }
      else
         implies = true;

      // Check the method interface
      if (implies == true && methodInterface != null)
      {
         implies = methodInterface.equals(perm.methodInterface);
      }
      // Check the method signature
      if (implies == true && methodSig != null)
      {
         implies = methodSig.equals(perm.methodSig);
      }

      return implies;
   }

   /**
    * <p>
    * Returns the {@code String} representation of this permission, which has the following form:
    * 
    * <pre>
    * [methodInterface:methodName(params)]
    * </pre>
    * 
    * </p>
    */
   @Override
   public String toString()
   {
      StringBuffer tmp = new StringBuffer(super.toString());
      tmp.append('[');
      if (methodInterface != null)
      {
         tmp.append(methodInterface);
         tmp.append(':');
      }
      else
      {
         tmp.append("*:");
      }
      if (methodName != null)
      {
         tmp.append(methodName);
      }
      else
      {
         tmp.append("*");
      }
      tmp.append('(');
      if (methodSig != null)
      {
         tmp.append(methodSig);
      }
      tmp.append(")]");
      return tmp.toString();
   }

   /**
    * <p>
    * Converts the specified method parameter classes to {@code String}.
    * </p>
    * 
    * @param params
    *           - the array of classes to be converted.
    * @return a {@code String[]} containing the classes names as {@code String}.
    */
   private static String[] convertParameters(Class<?>[] params)
   {
      List<String> tmp = new ArrayList<String>();
      for (Class<?> c : params)
      {
         if (c.isArray())
         {
            StringBuffer sb = new StringBuffer();
            Class<?> subType = c.getComponentType();
            sb.append(subType.getName());
            // Convert to type[][]...[]
            while (subType != null)
            {
               sb.append("[]");
               subType = subType.getComponentType();
            }
            tmp.add(sb.toString());
         }
         else
         {
            tmp.add(c.getName());
         }
      }
      String[] sig = new String[tmp.size()];
      tmp.toArray(sig);
      return sig;
   }

   /**
    * <p>
    * Parse the methodSpec string into methodName, methodInterface and methodSig.
    * </p>
    * 
    * <p>
    * The syntax of the methodSpec parameter is defined as follows:
    * </p>
    * 
    * <pre>
    * methodNameSpec ::= methodName | emptyString
    * 
    * methodInterfaceName ::= String
    * 
    * methodInterfaceSpec ::= methodInterfaceName | emptyString
    * 
    * typeName ::= typeName | typeName []
    * 
    * methodParams ::= typeName | methodParams comma typeName
    * 
    * methodParamsSpec ::= emptyString | methodParams
    * 
    * methodSpec ::= null | methodNameSpec | methodNameSpec comma methodInterfaceName | methodNameSpec comma
    * methodInterfaceSpec comma methodParamsSpec
    * </pre>
    * 
    * @param methodSpec
    *           - the string matching the format above
    */
   private void parseMethodSpec(String methodSpec)
   {
      methodName = null;
      methodInterface = null;
      methodSig = null;

      if (methodSpec != null)
      {
         StringTokenizer tokenizer = new StringTokenizer(methodSpec, ",", true);
         // Method name
         if (tokenizer.hasMoreTokens())
         {
            methodName = tokenizer.nextToken();
            if (methodName.equals(","))
               methodName = null;
         }
         // Method interface
         if (tokenizer.hasMoreTokens())
         {
            methodInterface = tokenizer.nextToken();
            if (methodName != null && methodInterface.equals(","))
               methodInterface = tokenizer.nextToken();
            if (methodInterface.equals(","))
            {
               methodInterface = null;
               methodSig = "";
            }
         }
         // Method args
         if (tokenizer.hasMoreTokens())
         {
            if (methodInterface != null)
               tokenizer.nextToken();
            StringBuffer tmp = new StringBuffer();
            while (tokenizer.hasMoreTokens())
            {
               tmp.append(tokenizer.nextToken());
            }
            methodSig = tmp.toString();
         }
      }
   }

   private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException
   {
      ObjectInputStream.GetField fields = ois.readFields();
      String actions = (String) fields.get("actions", null);
      parseMethodSpec(actions);
   }

   private void writeObject(ObjectOutputStream oos) throws IOException
   {
      ObjectOutputStream.PutField fields = oos.putFields();
      fields.put("actions", this.getActions());
      oos.writeFields();
   }
}
