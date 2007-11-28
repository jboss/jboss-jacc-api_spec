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
import java.io.ObjectStreamField;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Method;
import java.security.Permission;
import java.util.ArrayList;
import java.util.StringTokenizer;

import org.jboss.util.id.SerialVersion;

/** A security permission for ejb-method permissions.  The name of an
 * EJBMethodPermission contains the value of the ejb-name element in the
 * application's deployment descriptor that identifies the target EJB.
 * 
 * The actions of an EJBMethodPermission identifies the methods of the EJB to
 * which the permission applies.
 * 
 * Implementations of this class MAY implement newPermissionCollection or
 * inherit its implementation from the super class. 
 * 
 * @link http://java.sun.com/j2ee/1.4/docs/api/
 * 
 * @author Scott.Stark@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public final class EJBMethodPermission
   extends Permission
   implements Serializable
{
   /** @since 4.0.2 */
   private static final long serialVersionUID;
   static
   {
      if (SerialVersion.version == SerialVersion.LEGACY)
         serialVersionUID = 141000;
      else
         serialVersionUID = 1;
   }

   /**
    * @serialField actions String the actions string.
    */
    private static final ObjectStreamField[] serialPersistentFields = { 
        new ObjectStreamField("actions", String.class)
    };

   private transient String methodName;
   private transient String methodInterface;
   private transient String methodSig;

   /** Creates a new EJBMethodPermission with the specified name and actions.

    The name contains the value of the ejb-name element corresponding to an EJB
    in the application's deployment descriptor.

    The actions contains a methodSpec. The syntax of the actions parameter is
    defined as follows:

    methodNameSpec ::= methodName | emptyString

    methodInterfaceName ::= String

    methodInterfaceSpec ::= methodInterfaceName | emptyString

    typeName ::= typeName | typeName []

    methodParams ::= typeName | methodParams comma typeName

    methodParamsSpec ::= emptyString | methodParams

    methodSpec ::= null |
    methodNameSpec |
    methodNameSpec comma methodInterfaceName |
    methodNameSpec comma methodInterfaceSpec comma methodParamsSpec
 

    A MethodInterfaceName is a non-empty String and should contain a method-intf
    value as defined for use in EJB deployment descriptors. An implementation
    must be flexible such that it supports additional interface names especially
    if they are standardized by the EJB Specification. The EJB Specification
    currently defines the following method-intf values:

    { "Home", "LocalHome", "Remote", "Local", "ServiceEndpoint" }
 

    A null or empty string methodSpec indicates that the permission applies to
    all methods of the EJB. A methodSpec with a methodNameSpec of the empty
    string matches all methods of the EJB that match the methodInterface and
    methodParams elements of the methodSpec.

    A methodSpec with a methodInterfaceSpec of the empty string matches all
    methods of the EJB that match the methodNameSpec and methodParamsSpec
    elements of the methodSpec.

    A methodSpec without a methodParamsSpec matches all methods of the EJB that
    match the methodNameSpec and methodInterface elements of the methodSpec.

    The order of the typeNames in methodParams array must match the order of
    occurence of the corresponding parameters in the method signature of the
    target method(s). Each typeName in the methodParams must contain the
    canonical form of the corresponding parameter's typeName as defined by the
    getActions method. A methodSpec with an empty methodParamsSpec matches all
    0 argument methods of the EJB that match the methodNameSpec and
    methodInterfaceSpec elements of the methodSpec.

    * @param name - the ejb-name to which the permission pertains.
    * @param actions - identifies the methods of the EJB to which the permission
    * pertains.
    */
   public EJBMethodPermission(String name, String actions)
   {
      super(name);
      parseMethodSpec(actions);
   }

   /** Creates a new EJBMethodPermission with name corresponding to the EJBName
    * and actions composed from methodInterface, and the Method object.
    * 
    * A container uses this constructor prior to checking if a caller has
    * permission to call the method of an EJB.
    * 
    * @param ejbName - the ejb-name of the target EJB
    * @param methodInterface - A string that may be used to specify the EJB
    * interface to which the permission pertains. A value of null or "",
    * indicates that the permission pertains to all methods that match the other
    * parameters of the permission specification without consideration of the
    * interface they occur on.
    * @param method - an instance of the Java.lang.reflect.Method class
    * corresponding to the method that the container is trying to determine
    * whether the caller has permission to access. This value must not be null.
    */
   public EJBMethodPermission(String ejbName, String methodInterface, Method method)
   {
      this(ejbName, method.getName(), methodInterface,
         convertParameters(method.getParameterTypes()));
   }

   /** Creates a new EJBMethodPermission with name corresponding to the EJBName
    * and actions composed from methodName, methodInterface, and methodParams.
    * 
    * @param ejbName - the ejb-name of the target EJB
    * @param methodName - A string that may be used to indicate the method of the
    * EJB to which the permission pertains. A value of null or "" indicates that
    * the permission pertains to all methods that match the other parameters of
    * the permission specification without consideration of method name.
    * @param methodInterface - A string that may be used to specify the EJB
    * interface to which the permission pertains. A value of null or "",
    * indicates that the permission pertains to all methods that match the
    * other parameters of the permission specification without consideration of
    * the interface they occur on.
    * @param methodParams - An array of strings that may be used to specify
    * (by typeNames) the parameter signature of the target methods. The order of
    * the typeNames in methodParams array must match the order of occurence of
    * the corresponding parameters in the method signature of the target
    * method(s). Each typeName in the methodParams array must contain the
    * canonical form of the corresponding parameter's typeName as defined by the
    * getActions method. An empty methodParams array is used to represent a
    * method signature with no arguments. A value of null indicates that the
    * permission pertains to all methods that match the other parameters of the
    * permission specification without consideration of method signature.
    */
   public EJBMethodPermission(String ejbName, String methodName,
      String methodInterface, String[] methodParams)
   {
      super(ejbName);
      this.methodInterface = methodInterface;
      this.methodName = methodName;
      if( methodParams == null )
         methodSig = null;
      else
      {
         StringBuffer tmp = new StringBuffer();
         for(int n = 0; n < methodParams.length; n ++)
         {
            tmp.append(methodParams[n]);
            tmp.append(',');
         }
         if( tmp.length() > 0 )
            tmp.setLength(tmp.length()-1);
         methodSig = tmp.toString();
      }
   }

   /** Compare two EJBMethodPermissions.
    * 
    * @param p the EJBMethodPermission instance to compare against
    * @return true if p equates to this permission, false otherwise
    */
   public boolean equals(Object p)
   {
      boolean equals = false;
      if( p == null || !(p instanceof EJBMethodPermission) )
         return false;
      EJBMethodPermission perm = (EJBMethodPermission) p;
      equals = getName().equals(perm.getName());
      if( equals == true )
      {
         // Check the method names
         if( methodName != null )
         {
            if( perm.methodName == null )
               return false;
            if( methodName.equals(perm.methodName) == false )
               return false;
         }
         else if( perm.methodName != null )
         {
            return false;
         }

         // Check the method interfaces
         equals = methodInterface != perm.methodInterface;
         if( equals == false && methodInterface != null )
            equals = methodInterface.equals(perm.methodInterface);
         if( equals == false )
            return false;

         // Check the method parameters
         if( methodSig != null )
         {
            equals = perm.methodSig != null &&
               methodSig.equals(perm.methodSig);
         }
         else
         {
            equals = perm.methodSig == null;
         }
      }
      return equals;
   }

   /** Calculates the hash code as the hash of the methodName,
    *    methodInterface and methodSig for each that is non-null.
    * @return has the method represented.
    */ 
   public int hashCode()
   {
      int hashCode = 0;
      if( methodName != null )
         hashCode += methodName.hashCode();
      if( methodInterface != null )
         hashCode += methodInterface.hashCode();
      if( methodSig != null )
         hashCode += methodSig.hashCode();
      return hashCode;
   }

   /** Returns a String containing a canonical representation of the actions of
    this EJBMethodPermission. The Canonical form of the actions of an
    EJBMethodPermission is described by the following syntax description.

    methodNameSpec ::= methodName | emptyString
    methodInterfaceName ::= String
    methodInterfaceSpec ::= methodInterfaceName | emptyString
    typeName ::= typeName | typeName []
    methodParams ::= typeName | methodParams comma typeName
    methodParamsSpec ::= emptyString | methodParams
    methodSpec ::= null |
    methodName |
    methodNameSpec comma methodInterfaceName |
    methodNameSpec comma methodInterfaceSpec comma methodParamsSpec
 

    The canonical form of each typeName must begin with the fully qualified Java
    name of the corresponding parameter's type. The canonical form of a typeName
    for an array parameter is the fully qualified Java name of the array's
    component type followed by as many instances of the string "[]" as there are
    dimensions to the array. No additional characters (e.g. blanks) may occur in
    the canonical form.

    A MethodInterfaceName is a non-empty String and should contain a method-intf
    value as defined for use in EJB deployment descriptors. An implementation
    must be flexible such p it supports additional interface names especially
    if they are standardized by the EJB Specification. The EJB Specification
    currently defines the following method-intf values:
    { "Home", "LocalHome", "Remote", "Local", "ServiceEndpoint" }
 
    @return the canonicalized actions of this EJBMethodPermission
    */
   public String getActions()
   {
      StringBuffer actions = new StringBuffer();
      if( methodName != null )
         actions.append(methodName);
      if( methodInterface != null )
      {
         actions.append(',');
         actions.append(methodInterface);
      }
      else if( methodSig != null )
      {
         actions.append(',');         
      }

      if( methodSig != null )
      {
         actions.append(',');
         actions.append(methodSig);
      }
      String methodSpec = null;
      if( actions.length() > 0 )
         methodSpec = actions.toString();
      return methodSpec;
   }

   /** Determines if the argument Permission is "implied by" this
    * EJBMethodPermission. For this to be the case the following must apply:
    * The argument must be an instanceof EJBMethodPermission
    * with name equivalent to p of this EJBMethodPermission, and
    * the methods to which the argument permission applies (as defined in its actions)
    * must be a subset of the methods to which this EJBMethodPermission applies
    * (as defined in its actions). 
    *
    * The argument permission applies to a subset of the methods to which this
    * permission applies if all of the following conditions are met:
    * - the method name component of the methodNameSpec of this permission is null,
    * the empty string, or equivalent to the method name of the argument permission
    * - the method interface component of the methodNameSpec of this permission
    * is null, the empty string, or equivalent to the method interface of the
    * argument permission
    * - the method parameter list component of the methodNameSpec of this
    * permission is null, the empty string, or equivalent to the method
    * parameter list of the argument permission.
    * 
    * The name and actions comparisons described above are case sensitive. 
    * 
    * @param p the EJBMethodPermission checked to see if it this.
    * @return true if the specified permission is implied by this object, false if not
    */
   public boolean implies(Permission p)
   {
      boolean implies = false;
      if( p == null || !(p instanceof EJBMethodPermission) )
         return false;
      EJBMethodPermission perm = (EJBMethodPermission) p;
      implies = getName().equals(perm.getName());
      if( implies == false )
         return false;

      // See if perm is a subset of the method names
      if( methodName != null )
      {
         implies = methodName.equals(perm.methodName);
      }
      else
         implies = true;

      // Check the method interface
      if( implies == true && methodInterface != null )
      {
         implies = methodInterface.equals(perm.methodInterface);
      }
      // Check the method signature
      if( implies == true && methodSig != null && !methodSig.equals("") )
      {
         implies = methodSig.equals(perm.methodSig);
      }      

      return implies;
   } 

   private static String[] convertParameters(Class[] params)
   {
      ArrayList tmp = new ArrayList();
      for(int p = 0; p < params.length; p++)
      {
         Class c = params[p];
         if( c.isArray() )
         {
            StringBuffer sb = new StringBuffer();
            Class subType = c.getComponentType();
            sb.append(subType.getName());
            // Convert to type[][]...[]
            while( subType != null )
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

   /** Parse the methodSpec string into methodName, methodInterface and methodSig.

     The syntax of the methodSpec parameter is defined as follows:

     methodNameSpec ::= methodName | emptyString

     methodInterfaceName ::= String

     methodInterfaceSpec ::= methodInterfaceName | emptyString

     typeName ::= typeName | typeName []

     methodParams ::= typeName | methodParams comma typeName

     methodParamsSpec ::= emptyString | methodParams

     methodSpec ::= null |
     methodNameSpec |
     methodNameSpec comma methodInterfaceName |
     methodNameSpec comma methodInterfaceSpec comma methodParamsSpec

    @param methodSpec the string matching the format above
    */ 
   private void parseMethodSpec(String methodSpec)
   {
      methodName = null;
      methodInterface = null;
      methodSig = null;

      if( methodSpec != null )
      {
         StringTokenizer tokenizer = new StringTokenizer(methodSpec, ",", true);
         // Method name
         if( tokenizer.hasMoreTokens() )
         {
            methodName = tokenizer.nextToken();
            if( methodName.equals(",") )
               methodName = null;
         }
         // Method interface
         if( tokenizer.hasMoreTokens() )
         {
            methodInterface = tokenizer.nextToken();
            if( methodName != null && methodInterface.equals(",") )
               methodInterface = tokenizer.nextToken();
            if( methodInterface.equals(",") )
            {
               methodInterface = null;
               methodSig = "";
            }
         }
         // Method args
         if( tokenizer.hasMoreTokens() )
         {
            if( methodInterface != null )
               tokenizer.nextToken();
            StringBuffer tmp = new StringBuffer();
            while( tokenizer.hasMoreTokens() )
            {
               tmp.append(tokenizer.nextToken());
            }
            methodSig = tmp.toString();
         }
      }
   }

   // Private -------------------------------------------------------
   private void readObject(ObjectInputStream ois)
      throws ClassNotFoundException, IOException
   {
      ObjectInputStream.GetField fields = ois.readFields();
      String actions = (String) fields.get("actions", null);
      parseMethodSpec(actions);
   }

   private void writeObject(ObjectOutputStream oos)
      throws IOException
   {
      ObjectOutputStream.PutField fields =  oos.putFields();
      fields.put("actions",this.getActions());
      oos.writeFields();
   }
}
