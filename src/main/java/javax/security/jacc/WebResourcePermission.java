package javax.security.jacc;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.Serializable;
import java.security.Permission;
import java.util.StringTokenizer;
import java.util.TreeSet;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>
 * Class for Servlet web resource permissions. A {@code WebResourcePermission} is a named permission and has actions.
 * </p>
 * 
 * <p>
 * The name of a {@code WebResourcePermission} (also referred to as the target name) identifies the Web resources to
 * which the permission pertains.
 * </p>
 * 
 * <p>
 * Implementations of this class MAY implement {@code newPermissionCollection} or inherit its implementation from the
 * super class.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link Permission}
 */
@SuppressWarnings({"unchecked", "unused"})
public final class WebResourcePermission extends Permission implements Serializable
{
   /** @since 4.0.2 */
   private static final long serialVersionUID = 1;

   private static TreeSet<String> ALL_HTTP_METHODS = new TreeSet<String>();

   static final String ENCODED_COLON = "%3A";
   
   /**
    * @serialField actions String the actions string.
    */
   private static final ObjectStreamField[] serialPersistentFields = {new ObjectStreamField("actions", String.class)};

   static
   {
      ALL_HTTP_METHODS.add("GET");
      ALL_HTTP_METHODS.add("POST");
      ALL_HTTP_METHODS.add("PUT");
      ALL_HTTP_METHODS.add("DELETE");
      ALL_HTTP_METHODS.add("HEAD");
      ALL_HTTP_METHODS.add("OPTIONS");
      ALL_HTTP_METHODS.add("TRACE");
   }

   private transient URLPatternSpec urlSpec;

   private transient TreeSet<String> httpMethods;

   private transient String httpMethodsString;

   private transient TreeSet<String> httpExceptionList;

   private transient String httpExceptionString;

   /**
    * <p>
    * Creates a new WebResourcePermission from the HttpServletRequest object.
    * </p>
    * 
    * @param request
    *           - the {@code HttpServletRequest} object corresponding to the Servlet operation to which the permission
    *           pertains. The permission name is the substring of the requestURI ({@code
    *           HttpServletRequest.getRequestURI()}) that begins after the contextPath ({@code
    *           HttpServletRequest.getContextPath()}). When the substring operation yields the string “/”, the
    *           permission is constructed with the empty string as its name. The permission’s actions field is obtained
    *           from {@code HttpServletRequest.getMethod()}. The constructor must transform all colon characters
    *           occurring in the name to escaped encoding as defined in RFC 2396.
    */
   public WebResourcePermission(HttpServletRequest request)
   {
      this(requestURI(request), request.getMethod());
   }

   /**
    * <p>
    * Creates a new WebResourcePermission with the specified name and actions.
    * </p>
    * 
    * <p>
    * The name contains a URLPatternSpec that identifies the web resources to which the permissions applies. The syntax
    * of a URLPatternSpec is as follows:
    * </p>
    * 
    * <pre>
    * URLPatternList ::= URLPattern | URLPatternList colon URLPattern
    * 
    * URLPatternSpec ::= null | URLPattern | URLPattern colon URLPatternList
    * </pre>
    * 
    * <p>
    * A null URLPatternSpec is translated to the default URLPattern, "/", by the permission constructor. The empty
    * string is an exact URLPattern, and may occur anywhere in a URLPatternSpec that an exact URLPattern may occur. The
    * first URLPattern in a URLPatternSpec may be any of the pattern types, exact, path-prefix, extension, or default as
    * defined in the <i>Java Servlet Specification</i>). When a URLPatternSpec includes a URLPatternList, the patterns
    * of the URLPatternList identify the resources to which the permission does NOT apply and depend on the pattern type
    * and value of the first pattern as follows:
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
    * The actions parameter contains a comma separated list of HTTP methods. The syntax of the actions parameter is
    * defined as follows:
    * </p>
    * 
    * <pre>
    * ExtensionMethod ::= any token as defined by RFC 2616
    *           (that is, 1*[any CHAR except CTLs or separators])
    * 
    * HTTPMethod ::= "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE | ExtensionMethod"
    * 
    * HTTPMethodList ::= HTTPMethod | HTTPMethodList comma HTTPMethod
    * 
    * HTTPMethodExceptionList ::= exclaimationPoint HTTPMethodList
    * 
    * HTTPMethodSpec ::= null | HTTPMethodExceptionList | HTTPMethodList
    * </pre>
    * 
    * <p>
    * If duplicates occur in the HTTPMethodSpec they must be eliminated by the permission constructor.
    * </p>
    * 
    * <p>
    * A null or empty string HTTPMethodSpec indicates that the permission applies to all HTTP methods at the resources
    * identified by the URL pattern.
    * </p>
    * 
    * <p>
    * If the HTTPMethodSpec contains an HTTPMethodExceptionList (i.e., it begins with an exclamation- Point), the
    * permission pertains to all methods except those occurring in the exception list.
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
    *           - identifies the HTTP methods to which the permission pertains. If the value passed through this
    *           parameter is null or the empty string, then the permission is constructed with actions corresponding to
    *           all the possible HTTP methods.
    */
   public WebResourcePermission(String name, String actions)
   {
      super(name == null ? "/" : name);
      if (name == null)
         name = "/";
      this.urlSpec = new URLPatternSpec(name);
      parseActions(actions);
   }

   /**
    * <p>
    * Creates a new WebResourcePermission with name corresponding to the URLPatternSpec, and actions composed from the
    * array of HTTP methods.
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
    *           actions corresponding to all the possible HTTP methods.
    */
   public WebResourcePermission(String urlPatternSpec, String[] httpMethods)
   {
      super(urlPatternSpec);
      this.urlSpec = new URLPatternSpec(urlPatternSpec);
      Object[] methodInfo = canonicalMethods(httpMethods);
      this.httpMethods = (TreeSet<String>) methodInfo[0];
      this.httpMethodsString = (String) methodInfo[1];
   }

   /**
    * <p>
    * Checks two WebResourcePermission objects for equality. WebResourcePermission objects are equivalent if their
    * URLPatternSpec and (canonicalized) actions values are equivalent. The URLPatternSpec of a refer- ence permission
    * is equivalent to that of an argument permission if their first patterns are equivalent, and the patterns of the
    * URLPatternList of the reference permission collectively match exactly the same set of pat- terns as are matched by
    * the patterns of the URLPatternList of the argument permission.
    * </p>
    * 
    * <p>
    * Two Permission objects, P1 and P2, are equivalent if and only if P1.implies(P2) && P2.implies(P1).
    * </p>
    * 
    * @param p
    *           - the WebResourcePermission object being tested for equality with this WebResourcePermission.
    * @return true if the argument WebResourcePermission object is equivalent to this WebResourcePermission.
    */
   @Override
   public boolean equals(Object p)
   {
      if (p instanceof WebResourcePermission == false)
         return false;
      WebResourcePermission perm = (WebResourcePermission) p;

      // Two permissions p1 and p2 are equivalent if and only if p1.implies(p2) and p2.implies(p1)
      return this.implies(perm) && perm.implies(this);
   }

   /**
    * <p>
    * Returns a canonical String representation of the actions of this WebResourcePermission. WebResourcePermission
    * actions are canonicalized by sorting the HTTP methods into ascending lexical order. There may be no duplicate HTTP
    * methods in the canonical form, and the canonical form of the set of all HTTP methods is the value null.
    * </p>
    * 
    * @return a String containing the canonicalized actions of this WebResourcePermission (or the null value).
    */
   @Override
   public String getActions()
   {
      return this.httpMethodsString;
   }

   /**
    * <p>
    * Returns the hash code value for this WebResourcePermission. The properties of the returned hash code must be as
    * follows:
    * <ul>
    * <li>During the lifetime of a Java application, the hashCode method must return the same integer value, every time
    * it is called on a WebResourcePermission object. The value returned by hashCode for a particular
    * WebResourcePermission need not remain consistent from one execution of an application to another.</li>
    * <li>If two WebResourcePermission objects are equal according to the equals method, then calling the hashCode
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
    * Determines if the argument Permission is "implied by" this WebResourcePermission. For this to be the case, all of
    * the following must be true:
    * <ul>
    * <li>The argument is an instance of WebResourcePermission</li>
    * <li>The first URLPattern in the name of the argument permission is matched by the first URLPattern in the name of
    * this permission.</li>
    * <li>The first URLPattern in the name of the argument permission is NOT matched by any URLPattern in the
    * URLPatternList of the URLPatternSpec of this permission.</li>
    * <li>If the first URLPattern in the name of the argument permission matches the first URLPattern in the
    * URLPatternSpec of this permission, then every URLPattern in the URLPatternList of the URLPatternSpec of this
    * permission is matched by a URLPattern in the URLPatternList of the argument permission.</li>
    * <li>The HTTP methods in the actions of the argument permission are a subset of the HTTP methods in the actions of
    * this permission.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * URLPattern matching is performed using the <i>Servlet matching</i> rules where two URL patterns match if they are
    * related as follows:
    * <ul>
    * <li>their pattern values are String equivalent, or</li>
    * <li>this pattern is the path-prefix pattern "/*", or</li>
    * <li>this pattern is a path-prefix pattern (that is, it starts with "/" and ends with "/*") and the argument
    * pattern starts with the substring of this pattern, minus its last 2 characters, and the next character of the
    * argument pattern, if there is one, is "/", or</li>
    * <li>this pattern is an extension pattern (that is, it starts with "*.") and the argument pattern ends with this
    * pattern, or - the reference pattern is the special default pattern, "/", which matches all argument patterns.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * All of the comparisons described above are case sensitive.
    * </p>
    * 
    * @param permission
    *           - “this” WebResourcePermission is checked to see if it implies the argument permission.
    * @return true if the specified permission is implied by this object, false if not.
    */
   @Override
   public boolean implies(Permission permission)
   {
      if (permission instanceof WebResourcePermission == false)
         return false;
      WebResourcePermission perm = (WebResourcePermission) permission;
      // Check the URL patterns
      boolean implies = this.urlSpec.implies(perm.urlSpec);
      if (implies == true)
      {
         if (this.httpExceptionList != null)
            implies = matchExceptionList(this.httpExceptionList, perm.httpExceptionList);
         // Check the http methods
         if (this.httpMethods != null && perm.httpMethods != null)
            implies = this.httpMethods.containsAll(perm.httpMethods);
      }
      return implies;
   }

   /**
    * <p>
    * Build a permission name from the substring of the {@code HttpServletRequest.getRequestURI()}) that begins after
    * the contextPath ({@code HttpServletRequest.getContextPath()}). When the substring operation yields the string "/",
    * the permission is constructed with the empty string as its name.
    * </p>
    * 
    * @param request
    *           - the Servlet request object.
    * @return the resource permission name.
    */
   static String requestURI(HttpServletRequest request)
   {
      String uri = request.getRequestURI();
      if (uri != null)
      {
         String contextPath = request.getContextPath();
         int length = contextPath == null ? 0 : contextPath.length();
         if (length > 0)
         {
            uri = uri.substring(length);
         }
         if (uri.equals("/"))
         {
            uri = "";
         }
      }
      else
      {
         uri = "";
      }
      
      // according to the JACC specification, all colons within the request URI must be escaped.
      if (uri.indexOf(':') > 0)
         uri = uri.replaceAll(":", ENCODED_COLON);
      return uri;
   }

   static Object[] canonicalMethods(String methods)
   {
      String[] methodsArray = null;
      if (methods != null && methods.length() > 0)
         methodsArray = methods.split(",");

      return canonicalMethods(methodsArray);
   }

   static Object[] canonicalMethods(String[] methods)
   {
      // add the HTTP methods to a set to remove duplicates.
      TreeSet<String> actions = new TreeSet<String>();
      if (methods != null)
      {
         for (String method : methods)
            actions.add(method);
      }
      return canonicalMethods(actions);
   }

   static Object[] canonicalMethods(TreeSet<String> actions)
   {
      Object[] info = {ALL_HTTP_METHODS, null};
      if (actions.equals(ALL_HTTP_METHODS) || actions.size() == 0)
         return info;

      info[0] = actions;
      StringBuffer tmp = new StringBuffer();
      for (String action : actions)
      {
         tmp.append(action);
         tmp.append(',');
      }
      if (tmp.length() > 0)
         tmp.setLength(tmp.length() - 1);
      info[1] = tmp.toString();
      return info;
   }

   // Private -------------------------------------------------------
   private void parseActions(String actions)
   {
      boolean exclusionListNeeded = actions != null && actions.startsWith("!");
      if (exclusionListNeeded)
         actions = actions.substring(1);

      Object[] methodInfo = canonicalMethods(actions);
      if (exclusionListNeeded)
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

   static boolean matchExceptionList(TreeSet<String> myExceptionList, TreeSet<String> matchingExceptionList)
   {
      boolean bothnull = (myExceptionList == null && matchingExceptionList == null);
      boolean onenull = (myExceptionList == null && matchingExceptionList != null)
            || (myExceptionList != null && matchingExceptionList == null);

      if (bothnull)
         return true;
      if (onenull)
         return false;

      // matchingExceptionList must be a superset of myExceptionList
      for (String httpMethod : myExceptionList)
      {
         if (!matchingExceptionList.contains(httpMethod))
            return false;
      }
      return true;
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
