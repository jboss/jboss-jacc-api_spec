package javax.security.jacc;

import java.io.Serializable;
import java.io.ObjectStreamField;
import java.io.ObjectInputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.Permission;
import java.util.TreeSet;
import javax.servlet.http.HttpServletRequest;

/**
 * <p>
 * Class for Servlet Web user data permissions. A WebUserDataPermission is a named permission and has actions.
 * </p>
 * 
 * <p>
 * The name of a WebUserDataPermission (also referred to as the target name) identifies a Web resource by its context
 * path relative URL pattern.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:anil.saldhana@jboss.org">Anil Saldhana</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link Permission}
 */
@SuppressWarnings({"unused", "unchecked"})
public final class WebUserDataPermission extends Permission implements Serializable
{
   /** @since 4.0.2 */
   private static final long serialVersionUID = 1;

   /**
    * @serialField actions String the actions string.
    */
   private static final ObjectStreamField[] serialPersistentFields = {new ObjectStreamField("actions", String.class)};

   private transient URLPatternSpec urlSpec;

   private transient String httpMethodsString;

   private transient String transportType;

   private transient TreeSet<String> httpMethods;

   private transient TreeSet<String> httpExceptionList;

   private transient String httpExceptionString;

   /**
    * <p>
    * Creates a new WebUserDataPermission from the HttpServletRequest object.
    * </p>
    * 
    * @param request
    *           - the HttpServletRequest object corresponding to the Servlet operation to which the permission pertains.
    *           The permission name is the substring of the requestURI (HttpServletRequest.getRequestURI()) that begins
    *           after the contextPath (HttpServletRequest.getContextPath()). When the substring operation yields the
    *           string “/”, the permission is constructed with the empty string as its name. The constructor must
    *           transform all colon characters occurring in the name to escaped encoding as defined in RFC 2396. The HTTP
    *           method component of the permission’s actions is as obtained from HttpServletRequest.getMethod(). The
    *           TransportType component of the permission’s actions is determined by calling
    *           HttpServletRequest.isSecure().
    */
   public WebUserDataPermission(HttpServletRequest request)
   {
      this(WebResourcePermission.requestURI(request), requestActions(request));
   }

   /**
    * <p>
    * Creates a new WebUserDataPermission with the specified name and actions.
    * </p>
    * 
    * <p>
    * The name contains a URLPatternSpec that identifies the web resources to which the permissions applies. The syntax
    * of a URLPatternSpec is as follows:
    * 
    * <pre>
    * URLPatternList ::= URLPattern | URLPatternList colon URLPattern
    * 
    * URLPatternSpec ::= null | URLPattern | URLPattern colon URLPatternList
    * </pre>
    * 
    * </p>
    * 
    * <p>
    * A null URLPatternSpec is translated to the default URLPattern, "/", by the permission constructor. The empty
    * string is an exact URLPattern, and may occur anywhere in a URLPatternSpec that an exact URLPattern may occur. The
    * first URLPattern in a URLPatternSpec may be any of the pattern types, exact, path-prefix, extension, or default as
    * defined in the Java Servlet Specification). When a URLPatternSpec includes a URLPatternList, the patterns of the
    * URLPatternList identify the resources to which the permission does NOT apply and depend on the pattern type and
    * value of the first pattern as follows:
    * <ul>
    * <li>No pattern may exist in the URLPatternList that matches the first pattern.</li>
    * <li>If the first pattern is a path-prefix pattern, only exact patterns matched by the first pattern and
    * path-prefix patterns matched by, but different from, the first pattern may occur in the URLPatternList.</li>
    * <li>If the first pattern is an extension pattern, only exact patterns that are matched by the first pattern and
    * path-prefix patterns may occur in the URLPatternList.</li>
    * <li>If the first pattern is the default pattern, "/", any pattern except the default pattern may occur in the
    * URLPatternList.</li>
    * <li>If the first pattern is an exact pattern a URLPatternList must not be present in the URLPatternSpec.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * The actions parameter contains a comma separated list of HTTP methods that may be followed by a transportType
    * separated from the HTTP method by a colon.
    * 
    * <pre>
    * ExtensionMethod ::= any token as defined by RFC 2616
    *         (that is, 1*[any CHAR except CTLs or separators])
    * 
    * HTTPMethod ::= "Get" | "POST" | "PUT" | "DELETE" | "HEAD" |
    *         "OPTIONS" | "TRACE" | ExtensionMethod
    * 
    * HTTPMethodList ::= HTTPMethod | HTTPMethodList comma HTTPMethod
    * 
    * HTTPMethodExceptionList ::= exclaimationPoint HTTPMethodList
    * 
    * HTTPMethodSpec ::= emptyString | HTTPMethodExceptionList |
    *         HTTPMethodList
    * 
    * transportType ::= "INTEGRAL" | "CONFIDENTIAL" | "NONE"
    * 
    * actions ::= null | HTTPMethodSpec |
    *         HTTPMethodSpec colon transportType
    * </pre>
    * 
    * </p>
    * 
    * <p>
    * If duplicates occur in the HTTPMethodSpec they must be eliminated by the permission constructor.
    * </p>
    * 
    * <p>
    * An empty string HTTPMethodSpec is a shorthand for a List containing all the possible HTTP methods.
    * </p>
    * 
    * <p>
    * An actions string without a transportType is a shorthand for a actions string with the value "NONE" as its
    * TransportType.
    * </p>
    * 
    * <p>
    * A granted permission representing a transportType of "NONE", indicates that the associated resources may be
    * accessed using any connection type.
    * </p>
    * 
    * @param name
    *           - the URLPatternSpec that identifies the application specific web resources to which the permission
    *           pertains. All URLPatterns in the URLPatternSpec are relative to the context path of the deployed web
    *           application module, and the same URLPattern must not occur more than once in a URLPatternSpec. A null
    *           URLPatternSpec is translated to the default URLPattern, “/”, by the permission constructor. All colons
    *           occurring within the URLPattern elements of the URLPatternSpec must be represented in escaped encoding
    *           as defined in RFC 2396.
    * @param actions
    *           - identifies the HTTP methods and transport type to which the permission pertains. If the value passed
    *           through this parameter is null or the empty string, then the permission is constructed with actions
    *           corresponding to all the possible HTTP methods and transportType "NONE".
    */
   public WebUserDataPermission(String name, String actions)
   {
      super(name == null ? "/" : name);
      if (name == null)
         name = "/";
      this.urlSpec = new URLPatternSpec(name);
      parseActions(actions);
   }

   /**
    * <p>
    * Creates a new WebUserDataPermission with name corresponding to the URLPatternSpec, and actions composed from the
    * array of HTTP methods and the transport type.
    * </p>
    * 
    * @param urlPatternSpec
    *           - the URLPatternSpec that identifies the application specific web resources to which the permission
    *           pertains. All URLPatterns in the URLPatternSpec are relative to the context path of the deployed web
    *           application module, and the same URLPattern must not occur more than once in a URLPatternSpec. A null
    *           URLPatternSpec is translated to the default URLPattern, “/”, by the permission constructor. All colons
    *           occurring within the URLPattern elements of the URLPatternSpec must be represented in escaped encoding
    *           as defined in RFC 2396.
    * @param httpMethods
    *           - an array of strings each element of which contains the value of an HTTP method. If the value passed
    *           through this parameter is null or is an array with no elements, then the permission is constructed with
    *           actions containing all the possible HTTP methods.
    * @param transportType
    *           - a String whose value is a transportType. If the value passed through this parameter is null, then the
    *           permission is constructed with actions containing transportType "NONE".
    */
   public WebUserDataPermission(String urlPatternSpec, String[] httpMethods, String transportType)
   {
      super(urlPatternSpec);
      this.urlSpec = new URLPatternSpec(urlPatternSpec);
      Object[] methodInfo = WebResourcePermission.canonicalMethods(httpMethods);
      this.httpMethods = (TreeSet<String>) methodInfo[0];
      this.httpMethodsString = (String) methodInfo[1];
      if (transportType != null && transportType.equalsIgnoreCase("NONE"))
         transportType = null;
      this.transportType = transportType;
   }

   /**
    * <p>
    * Checks two WebUserDataPermission objects for equality. WebUserDataPermission objects are equivalent if their
    * URLPatternSpec and (canonicalized) actions values are equivalent. The URLPatternSpec of a reference permission is
    * equivalent to that of an argument permission if their first patterns are equivalent, and the patterns of the
    * URLPatternList of the reference permission collectively match exactly the same set of patterns as are matched by
    * the patterns of the URLPatternList of the argument permission.
    * </p>
    * 
    * <p>
    * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) && P2.implies(P1).
    * </p>
    * 
    * @param p
    *           - the WebUserDataPermission object being tested for equality with this WebUserDataPermission.
    * @return true if the argument WebUserDataPermission object is equivalent to this WebUserDataPermission.
    */
   @Override
   public boolean equals(Object p)
   {
      // boolean equals = false;
      if (p == null || !(p instanceof WebUserDataPermission))
         return false;
      WebUserDataPermission perm = (WebUserDataPermission) p;
      /**
       * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) && P2.implies(P1).
       */
      return this.implies(perm) && perm.implies(this);
   }

   /**
    * <p>
    * Returns a canonical String representation of the actions of this WebUserDataPermission. The canonical form of the
    * actions of a WebUserDataPermission is described by the following syntax description.
    * 
    * <pre>
    * ExtensionMethod ::= any token as defined by RFC 2616
    *          (that is, 1*[any CHAR except CTLs or separators])
    * HTTPMethod ::= "GET" | "POST" | "PUT" | "DELETE" | "HEAD" |
    *          "OPTIONS" | "TRACE" | ExtensionMethod
    * HTTPMethodList ::= HTTPMethod | HTTPMethodList comma HTTPMethod
    * HTTPMethodExceptionList ::= exclaimationPoint HTTPMethodList
    * HTTPMethodSpec ::= emptyString | HTTPMethodExceptionList |
    *         HTTPMethodList
    * transportType ::= "INTEGRAL" | "CONFIDENTIAL" | "NONE"
    * actions ::= null | HTTPMethodList |
    *         HTTPMethodSpec colon transportType
    * </pre>
    * 
    * </p>
    * 
    * <p>
    * If the permission's HTTP methods include the entire HTTP method set and the permission's transport type is
    * "INTEGRAL" or "CONFIDENTIAL", the HTTP methods shall be represented in the canonical form by an empty string
    * HTTPMethodSpec. If the permission's HTTP methods include the entire HTTP method set and the permission's transport
    * type is not "INTEGRAL"or "CONFIDENTIAL", the canonical actions value shall be the null value.
    * </p>
    * 
    * <p>
    * If the permission's methods do not include the entire HTTP method set, duplicates must be eliminated and the
    * remaining elements must be sorted into ascending lexical order. The resulting HTTPMethodList must be included in
    * the canonical form, and if the permission's transport type is not "INTEGRAL" or "CONFIDENTIAL", the canonical
    * actions value must be exactly the resulting HTTPMethodList.
    * </p>
    * 
    * @return a String containing the canonicalized actions of this WebUserDataPermission (or the null value).
    */
   @Override
   public String getActions()
   {
      String actions = null;
      if (httpMethodsString != null)
      {
         if (transportType != null)
            actions = httpMethodsString + ":" + transportType;
         else
            actions = httpMethodsString;
      }
      else if (transportType != null)
      {
         actions = ":" + transportType;
      }
      return actions;
   }

   /**
    * <p>
    * Returns the hash code value for this WebUserDataPermission. The properties of the returned hash code must be as
    * follows:
    * <ul>
    * <li>During the lifetime of a Java application, the hashCode method shall return the same integer value every time
    * it is called on a WebUserDataPermission object. The value returned by hashCode for a particular EJBMethod
    * permission need not remain consistent from one execution of an application to another.</li>
    * <li>If two WebUserDataPermission objects are equal according to the equals method, then calling the hash- Code
    * method on each of the two Permission objects must produce the same integer result (within an application).</li>
    * </ul>
    * </p>
    * 
    * @return the integer hash code value for this object.
    */
   @Override
   public int hashCode()
   {
      int hashCode = 17;
      hashCode = 37 * hashCode + this.urlSpec.hashCode();
      if (this.httpMethods != null)
         hashCode = 37 * hashCode + this.httpMethods.hashCode();
      return hashCode;
   }

   /**
    * <p>
    * Determines if the argument Permission is "implied by" this WebUserDataPermission. For this to be the case all of
    * the following must be true:
    * <ul>
    * <li>The argument is an instance of WebUserDataPermission.</li>
    * <li>The first URLPattern in the name of the argument permission is matched by the first URLPattern in the name of
    * this permission.</li>
    * <li>The first URLPattern in the name of the argument permission is NOT matched by any URLPattern in the
    * URLPatternList of the URLPatternSpec of this permission.</li>
    * <li>If the first URLPattern in the name of the argument permission matches the first URLPattern in the
    * URLPatternSpec of this permission, then every URLPattern in the URLPatternList of the URLPatternSpec of this
    * permission is matched by a URLPattern in the URLPatternList of the argument permission.</li>
    * <li>The HTTP methods in the actions of the argument permission are a subset of the HTTP methods in the actions of
    * this permission.</li>
    * <li>The transportType in the actions of this permission either corresponds to the value "NONE", or equals the
    * transportType in the actions of the argument permission.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * URLPattern matching is performed using the <i>Servlet matching rules</i> where two URL patterns match if they are
    * related as follows:
    * <ul>
    * <li>their pattern values are String equivalent, or</li>
    * <li>this pattern is the path-prefix pattern "/*", or</li>
    * <li>this pattern is a path-prefix pattern (that is, it starts with "/" and ends with "/*") and the argument
    * pattern starts with the substring of this pattern, minus its last 2 characters, and the next character of the
    * argument pattern, if there is one, is "/", or</li>
    * <li>this pattern is an extension pattern (that is, it starts with "*.") and the argument pattern ends with this
    * pattern, or</li>
    * <li>the reference pattern is the special default pattern, "/", which matches all argument patterns.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * All of the comparisons described above are case sensitive.
    * </p>
    * 
    * @param p
    *           - “this” WebUserDataPermission is checked to see if it implies the argument permission.
    * @return true if the specified permission is implied by this object, false if not.
    */
   @Override
   public boolean implies(Permission p)
   {
      if (p == null || !(p instanceof WebUserDataPermission))
         return false;
      WebUserDataPermission perm = (WebUserDataPermission) p;
      // Check the URL patterns
      boolean implies = urlSpec.implies(perm.urlSpec);
      if (implies == true)
      {
         if (httpExceptionList != null)
            implies = WebResourcePermission.matchExceptionList(httpExceptionList, perm.httpExceptionList);
         // Check the http methods
         if (httpMethods != null && perm.httpMethods != null)
            implies = httpMethods.containsAll(perm.httpMethods);
         // Check the transport guarantee
         if (implies == true && transportType != null)
            implies = transportType.equals(perm.transportType);
      }

      return implies;
   }

   // Private -------------------------------------------------------
   /**
    * Build the request permission actions from the HTTP method component using HttpServletRequest.getMethod() + the
    * TransportType component of the action from HttpServletRequest.isSecure().
    * 
    * @param request
    *           - the servlet request
    * @return the permission actions string
    */
   private static String requestActions(HttpServletRequest request)
   {
      String actions = request.getMethod() + (request.isSecure() ? ":CONFIDENTIAL" : "");
      return actions;
   }

   private void parseActions(String actions)
   {
      // Remove any transport spec
      if (actions != null)
      {
         int colon = actions.indexOf(':');
         if (colon >= 0)
         {
            this.transportType = actions.substring(colon + 1);
            if (transportType.equalsIgnoreCase("NONE"))
               transportType = null;
            actions = actions.substring(0, colon);
         }
      }
      boolean exceptionListNeeded = actions != null && actions.startsWith("!");

      Object[] methodInfo = WebResourcePermission.canonicalMethods(actions);
      if (exceptionListNeeded)
      {
         this.httpExceptionList = (TreeSet<String>) methodInfo[0];
         this.httpExceptionString = (String) methodInfo[1];
      }
      else
      {
         this.httpMethods = (TreeSet<String>) methodInfo[0];
         this.httpMethodsString = (String) methodInfo[1];
      }
   }

   private void readObject(ObjectInputStream ois) throws ClassNotFoundException, IOException
   {
      ObjectInputStream.GetField fields = ois.readFields();
      String actions = (String) fields.get("actions", null);
      parseActions(actions);
   }

   private void writeObject(ObjectOutputStream oos) throws IOException
   {
      ObjectOutputStream.PutField fields = oos.putFields();
      fields.put("actions", this.getActions());
      oos.writeFields();
   }
}
