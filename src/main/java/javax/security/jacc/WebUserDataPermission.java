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
import java.security.Permission;
import java.util.TreeSet;
import javax.servlet.http.HttpServletRequest;

import org.jboss.util.id.SerialVersion;

/** Class for Servlet Web user data permissions. A WebUserDataPermission is a
 * named permission and has actions.
 * 
 * The name of a WebUserDataPermission (also referred to as the target name)
 * identifies a Web resource by its context path relative URL pattern.
 *  
 * @link http://java.sun.com/j2ee/1.4/docs/api/
 * 
 * @author Scott.Stark@jboss.org
 * @author Anil.Saldhana@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public final class WebUserDataPermission
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

   private transient URLPatternSpec urlSpec;
   private transient String httpMethodsString;
   private transient String transportType;
   private transient TreeSet httpMethods;
   private transient TreeSet httpExceptionList;
   private transient String httpExceptionString;

   /** Creates a new WebUserDataPermission from the HttpServletRequest object.
    * 
    * @param request  - the HttpServletRequest object corresponding to the
    * Servlet operation to which the permission pertains. The permission name is
    * the substring of the requestURI (HttpServletRequest.getRequestURI()) that
    * begins after the contextPath (HttpServletRequest.getContextPath()). When
    * the substring operation yields the string "/", the permission is
    * constructed with the empty string as its name. The HTTP method component
    * of the permission's actions is as obtained from HttpServletRequest.getMethod().
    * The TransportType component of the permission's actions is determined by
    * calling HttpServletRequest.isSecure().
    */ 
   public WebUserDataPermission(HttpServletRequest request)
   {
      this(WebResourcePermission.requestURI(request),
         requestActions(request));
   }

   /** Creates a new WebUserDataPermission with the specified name and actions.
   The name contains a URLPatternSpec that identifies the web resources to which
    the permissions applies. The syntax of a URLPatternSpec is as follows:

          URLPatternList ::= URLPattern | URLPatternList colon URLPattern

          URLPatternSpec ::= null | URLPattern | URLPattern colon URLPatternList

   A null URLPatternSpec is translated to the default URLPattern, "/", by the
    permission constructor. The empty string is an exact URLPattern, and may
    occur anywhere in a URLPatternSpec that an exact URLPattern may occur.
    The first URLPattern in a URLPatternSpec may be any of the pattern types,
    exact, path-prefix, extension, or default as defined in the Java Servlet
    Specification). When a URLPatternSpec includes a URLPatternList, the
    patterns of the URLPatternList identify the resources to which the
    permission does NOT apply and depend on the pattern type and value of the
    first pattern as follows:

    - No pattern may exist in the URLPatternList that matches the first pattern.
    - If the first pattern is a path-prefix pattern, only exact patterns matched
    by the first pattern and path-prefix patterns matched by, but different from,
    the first pattern may occur in the URLPatternList.
    - If the first pattern is an extension pattern, only exact patterns that are
    matched by the first pattern and path-prefix patterns may occur in the
    URLPatternList.
    - If the first pattern is the default pattern, "/", any pattern except the
    default pattern may occur in the URLPatternList.
    - If the first pattern is an exact pattern a URLPatternList must not be
    present in the URLPatternSpec. 

   The actions parameter contains a comma separated list of HTTP methods that
    may be followed by a transportType separated from the HTTP method by a colon.

          HTTPMethod ::= "Get" | "POST" | "PUT" | "DELETE" | "HEAD" |
                  "OPTIONS" | "TRACE"

          HTTPMethodList ::= HTTPMethod | HTTPMethodList comma HTTPMethod

          HTTPMethodExceptionList ::= exclaimationPoint HTTPMethodList

          HTTPMethodSpec ::= emptyString | HTTPMethodExceptionList |
                  HTTPMethodList

          transportType ::= "INTEGRAL" | "CONFIDENTIAL" | "NONE"

          actions ::= null | HTTPMethodSpec | 
                  HTTPMethodSpec colon transportType
 

   If duplicates occur in the HTTPMethodSpec they must be eliminated by the
    permission constructor.

   An empty string HTTPMethodSpec is a shorthand for a List containing all the
    possible HTTP methods.

   An actions string without a transportType is a shorthand for a actions string
    with the value "NONE" as its TransportType.

   A granted permission representing a transportType of "NONE", indicates that
    the associated resources may be accessed using any conection type.

    @param name - the URLPatternSpec that identifies the application specific
    web resources to which the permission pertains. All URLPatterns in the
    URLPatternSpec are relative to the context path of the deployed web
    application module, and the same URLPattern must not occur more than once
    in a URLPatternSpec. A null URLPatternSpec is translated to the default
    URLPattern, "/", by the permission constructor.
    @param actions - identifies the HTTP methods and transport type to which
    the permission pertains. If the value passed through this parameter is
    null or the empty string, then the permission is constructed with actions
    corresponding to all the possible HTTP methods and transportType "NONE".
    */ 
   public WebUserDataPermission(String name, String actions)
   {
      super(name == null ? "/" : name);
      if( name == null )
         name = "/";
      this.urlSpec = new URLPatternSpec(name);
      parseActions(actions);
   }

   /** Creates a new WebUserDataPermission with name corresponding to the
    * URLPatternSpec, and actions composed from the array of HTTP methods and
    * the transport type.
    * 
    * @param urlPatternSpec - the URLPatternSpec that identifies the application
    * specific web resources to which the permission pertains. All URLPatterns
    * in the URLPatternSpec are relative to the context path of the deployed web
    * application module, and the same URLPattern must not occur more than once
    * in a URLPatternSpec. A null URLPatternSpec is translated to the default
    * URLPattern, "/", by the permission constructor.
    * @param httpMethods  - an array of strings each element of which contains
    * the value of an HTTP method. If the value passed through this parameter is
    * null or is an array with no elements, then the permission is constructed
    * with actions containing all the possible HTTP methods.
    * @param transportType - a String whose value is a transportType. If the
    * value passed through this parameter is null, then the permission is
    * constructed with actions containing transportType "NONE".
    */ 
   public WebUserDataPermission(String urlPatternSpec, String[] httpMethods,
      String transportType)
   {
      super(urlPatternSpec);
      this.urlSpec = new URLPatternSpec(urlPatternSpec);
      Object[] methodInfo = WebResourcePermission.canonicalMethods(httpMethods);
      this.httpMethods = (TreeSet) methodInfo[0];
      this.httpMethodsString = (String) methodInfo[1];
      if( transportType != null && transportType.equalsIgnoreCase("NONE") )
         transportType = null;
      this.transportType = transportType;
   }

   /** Checks two WebUserDataPermission objects for equality. WebUserDataPermission
    * objects are equivalent if their URLPatternSpec and (canonicalized) actions
    * values are equivalent. The URLPatternSpec of a reference permission is
    * equivalent to that of an argument permission if their first patterns are
    * equivalent, and the patterns of the URLPatternList of the reference
    * permission collectively match exactly the same set of patterns as are
    * matched by the patterns of the URLPatternList of the argument permission.
    * 
    * @param p - the WebUserDataPermission object being tested for equality.
    * @return true if the argument WebUserDataPermission object is equivalent to
    * this, false otherwise.
    */ 
   public boolean equals(Object p)
   {
      //boolean equals = false;
      if( p == null || !(p instanceof WebUserDataPermission) )
         return false;
      WebUserDataPermission perm = (WebUserDataPermission) p;
      /**
       * Two Permission objects, P1 and P2, are equivalent 
       * if and only if P1.implies(P2) && P2.implies(P1).
       */
      return this.implies(perm) && perm.implies(this);
      /*equals = urlSpec.equals(perm.urlSpec);
      if( equals == true )
      {
         String a0 = getActions();
         String a1 = perm.getActions();
         equals = (a0 != null && a0.equals(a1)) || (a0 == a1);
      }
      return equals;*/
   }

   /** Returns a canonical String representation of the actions of this
    * WebUserDataPermission. The canonical form of the actions of a
    * WebUserDataPermission is described by the following syntax description.
    *  HTTPMethod ::= "Get" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE"
    * HTTPMethodList ::= HTTPMethod | HTTPMethodList comma HTTPMethod
    * HTTPMethodSpec ::= emptyString | HTTPMethodList
    * transportType ::= "INTEGRAL" | "CONFIDENTIAL" | "NONE"
    * actions ::= null | HTTPMethodList | HTTPMethodSpec colon transportType
    *
    * If the permission's HTTP methods include the entire HTTP method set and
    * the permission's transport type is "INTEGRAL" or "CONFIDENTIAL", the HTTP
    * methods shall be represented in the canonical form by an empty string
    * HTTPMethodSpec. If the permission's HTTP methods include the entire HTTP
    * method set and the permission's transport type is not "INTEGRAL"or
    * "CONFIDENTIAL", the canonical actions value shall be the null value. If
    * the permission's methods do not include the entire HTTP method set,
    * duplicates must be eliminated and the remaining elements must be sorted
    * into ascending lexical order. The resulting HTTPMethodList must be
    * included in the canonical form, and if the permission's transport type is
    * not "INTEGRAL" or "CONFIDENTIAL", the canonical actions value must be
    * exactly the resulting HTTPMethodList.
    * 
    * @return a String containing the canonicalized actions of this
    * WebUserDataPermission (or the null value).
    */ 
   public String getActions()
   {
      String actions = null;
      if( httpMethodsString != null )
      {
         if( transportType != null )
            actions = httpMethodsString + ":" + transportType;
         else
            actions = httpMethodsString;
      }
      else if( transportType != null )
      {
         actions = ":" + transportType;
      }
      return actions;
   }

   /** Returns the hash code value for this WebUserDataPermission. The properties
    * of the returned hash code must be as follows:

    * - During the lifetime of a Java application, the hashCode method shall
    * return the same integer value every time it is called on a
    * WebUserDataPermission object. The value returned by hashCode for a
    * particular EJBMethod permission need not remain consistent from one
    * execution of an application to another.
    * - If two WebUserDataPermission objects are equal according to the equals
    * method, then calling the hashCode method on each of the two Permission
    * objects must produce the same integer result (within an application). 
    * @return the int hash code.
    */ 
   public int hashCode()
   {
      int hashCode = urlSpec.hash();
      if( httpMethods != null )
         hashCode += httpMethods.hashCode();
      return hashCode;
   }

   /** Determines if the argument Permission is "implied by" this
    * WebUserDataPermission. For this to be the case all of the following must
    * be true:

    * - The argument is an instanceof WebUserDataPermission.
    * - The first URLPattern in the name of the argument permission is matched
    * by the first URLPattern in the name of this permission.
    * - The first URLPattern in the name of the argument permission is NOT
    * matched by any URLPattern in the URLPatternList of the URLPatternSpec of
    * this permission.
    * - If the first URLPattern in the name of the argument permission matches
    * the first URLPattern in the URLPatternSpec of this permission, then every
    * URLPattern in the URLPatternList of the URLPatternSpec of this permission
    * is matched by a URLPattern in the URLPatternList of the argument
    * permission.
    * - The HTTP methods in the actions of the argument permission are a subset
    * of the HTTP methods in the actions of this permission.
    * - The transportType in the actions of this permission either corresponds
    * to the value "NONE", or equals the transportType in the actions of the
    * argument permission.
    * 
    * URLPattern matching is performed using the Servlet matching rules where
    * two URL patterns match if they are related as follows:

    * - their pattern values are String equivalent, or
    * - this pattern is the path-prefix pattern "/*", or
    * - this pattern is a path-prefix pattern (that is, it starts with "/" and
    * ends with "/*") and the argument pattern starts with the substring of this
    * pattern, minus its last 2 characters, and the next character of the
    * argument pattern, if there is one, is "/", or
    * - this pattern is an extension pattern (that is, it starts with "*.") and
    * the argument pattern ends with this pattern, or
    * - the reference pattern is the special default pattern, "/", which matches
    * all argument patterns.
    * 
    * All of the comparisons described above are case sensitive. 
    * 
    * @param p - the WebUserDataPermission to test
    * @return true if this implies the argument permission
    */ 
   public boolean implies(Permission p)
   {
      if( p == null || !(p instanceof WebUserDataPermission) )
         return false;
      WebUserDataPermission perm = (WebUserDataPermission) p;
      // Check the URL patterns
      boolean implies = urlSpec.implies(perm.urlSpec);
      if( implies == true )
      {
         if(httpExceptionList != null)
            implies = WebResourcePermission.matchExceptionList(httpExceptionList, 
                  perm.httpExceptionList); 
         //Check the http methods
         if( httpMethods != null && perm.httpMethods != null)
               implies = httpMethods.containsAll(perm.httpMethods);  
         // Check the transport guarentee
         if( implies == true && transportType != null )
            implies = transportType.equals(perm.transportType);
      }  
      
      return implies;
   }

   // Private -------------------------------------------------------
   /** Build the request permission actions from the HTTP method component
    * using HttpServletRequest.getMethod() + the TransportType component of the
    * action from HttpServletRequest.isSecure().
    * 
    * @param request - the servlet request
    * @return the permission actions string
    */ 
   private static String requestActions(HttpServletRequest request)
   {
      String actions = request.getMethod() +
         (request.isSecure() ? ":CONFIDENTIAL" : "");
      return actions;
   }

   private void parseActions(String actions)
   {
      // Remove any transport spec
      if( actions != null )
      {
         int colon = actions.indexOf(':');
         if( colon >= 0 )
         {
            this.transportType = actions.substring(colon+1);
            if( transportType.equalsIgnoreCase("NONE") )
               transportType = null;
            actions = actions.substring(0, colon);
         }
      }
      boolean exceptionListNeeded = actions != null && actions.startsWith("!");
      
      Object[] methodInfo = WebResourcePermission.canonicalMethods(actions);
      if(exceptionListNeeded)
      {
         this.httpExceptionList = (TreeSet) methodInfo[0];
         this.httpExceptionString = (String) methodInfo[1];
      }
      else
      { 
         this.httpMethods = (TreeSet) methodInfo[0];
         this.httpMethodsString = (String) methodInfo[1];
      }
   }

   private void readObject(ObjectInputStream ois)
      throws ClassNotFoundException, IOException
   {
      ObjectInputStream.GetField fields = ois.readFields();
      String actions = (String) fields.get("actions", null);
      parseActions(actions);
   }

   private void writeObject(ObjectOutputStream oos)
      throws IOException
   {
      ObjectOutputStream.PutField fields =  oos.putFields();
      fields.put("actions", this.getActions());
      oos.writeFields();
   }
}
