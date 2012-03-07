package javax.security.jacc;

import java.util.HashSet;

/**
 * <p>
 * Encapsulation of the <b>URLPatternSpec</b> defined in the {@code WebResourcePermission} and {@code
 * WebUserDataPermission} classes.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link WebResourcePermission}, {@link WebUserDataPermission}
 */
class URLPatternSpec
{
   /** The first or only URLPattern in the specification */
   URLPattern urlPattern;

   /** */
   HashSet<URLPattern> urlPatternList;

   /**
    * <p>
    * The specification contains a {@code URLPatternSpec} that identifies the web resources to which the permissions
    * applies. The syntax of a {@code URLPatternSpec} is as follows:
    * </p>
    * 
    * <pre>
    * URLPatternList ::= URLPattern | URLPatternList colon URLPattern 
    * URLPatternSpec ::= null | URLPattern | URLPattern colon URLPatternList
    * </pre>
    * 
    * <p>
    * A null {@code URLPatternSpec} is translated to the default {@code URLPattern}, "/", by the permission constructor.
    * The empty string is an exact {@code URLPattern}, and may occur anywhere in a {@code URLPatternSpec} that an exact
    * {@code URLPattern} may occur. The first {@code URLPattern} in a {@code URLPatternSpec} may be any of the pattern
    * types, exact, path-prefix, extension, or default as defined in the Java Servlet Specification). When a {@code
    * URLPatternSpec} includes a {@code URLPatternList}, the patterns of the {@code URLPatternList} identify the
    * resources to which the permission does NOT apply and depend on the pattern type and value of the first pattern as
    * follows:
    * <ul>
    * <li>No pattern may exist in the {@code URLPatternList} that matches the first pattern.</li>
    * <li>If the first pattern is a path-prefix pattern, only exact patterns matched by the first pattern and
    * path-prefix patterns matched by, but different from, the first pattern may occur in the {@code URLPatternList}.</li>
    * <li>If the first pattern is an extension pattern, only exact patterns that are matched by the first pattern and
    * path-prefix patterns may occur in the {@code URLPatternList}.</li>
    * <li>If the first pattern is the default pattern, "/", any pattern except the default pattern may occur in the
    * {@code URLPatternList}.</li>
    * <li>If the first pattern is an exact pattern a {@code URLPatternList} must not be present in the {@code
    * URLPatternSpec}.</li>
    * </ul>
    * </p>
    * 
    * @param spec
    *           the {@code String} representation of the {@code URLPatternSpec} as defined by the JACC specification.
    */
   URLPatternSpec(String spec)
   {
      if (spec == null)
         this.urlPattern = new URLPattern("/");
      else if (spec.indexOf(":") > 0)
      {
         String[] patterns = spec.split(":");
         this.urlPatternList = new HashSet<URLPattern>();
         for (String pattern : patterns)
         {
            URLPattern p = new URLPattern(pattern);
            if (this.urlPattern == null)
               this.urlPattern = p;
            else
            {
               // Enforce the constraints
               if (p.matches(this.urlPattern))
               {
                  /*
                   * No pattern may exist in the URLPatternList that matches the first pattern.
                   */
                  String msg = "1: URLPatternList item: " + pattern + " matches: " + this.urlPattern.getPattern();
                  throw new IllegalArgumentException(msg);
               }
               else if (this.urlPattern.isPrefix())
               {
                  /*
                   * If the first pattern is a path-prefix pattern, only exact patterns matched by the first pattern and
                   * path-prefix patterns matched by, but different from, the first pattern may occur in the
                   * URLPatternList.
                   */
                  if (p.isPrefix() == false && p.isExact() == false)
                  {
                     String msg = "2: URLPatternList item: " + pattern + " is not an exact or prefix pattern";
                     throw new IllegalArgumentException(msg);
                  }
               }
               else if (this.urlPattern.isExtension())
               {
                  /*
                   * If the first pattern is an extension pattern, only exact patterns that are matched by the first
                   * pattern and path-prefix patterns may occur in the URLPatternList.
                   */
                  if (p.isPrefix() == false && p.isExact() == false)
                  {
                     String msg = "3: URLPatternList item: " + pattern + " is not an exact or prefix pattern";
                     throw new IllegalArgumentException(msg);
                  }
               }
               else if (this.urlPattern.isDefault())
               {
                  /*
                   * If the first pattern is the default pattern, "/", any pattern except the default pattern may occur
                   * in the URLPatternList.
                   */
                  if (p.isDefault())
                  {
                     String msg = "4: URLPatternList item: " + pattern + " cannot be the default pattern";
                     throw new IllegalArgumentException(msg);
                  }
               }
               else if (this.urlPattern.isExact())
               {
                  /*
                   * If the first pattern is an exact pattern a URLPatternList must not be present in the
                   * URLPatternSpec.
                   */
                  String msg = "5: URLPatternList item: " + pattern + " is not allowed in an exact pattern";
                  throw new IllegalArgumentException(msg);
               }
               this.urlPatternList.add(p);
            }
         }
      }
      else
      {
         this.urlPattern = new URLPattern(spec);
      }
   }

   /**
    * <p>
    * Perform the permission {@code URLPattern} matching:
    * <ul>
    * <li>the first {@code URLPattern} in the name of the argument permission is matched by the first {@code URLPattern}
    * in the name of this permission.</li>
    * <li>the first {@code URLPattern} in the name of the argument permission is NOT matched by any {@code URLPattern}
    * in the {@code URLPatternList} of the {@code URLPatternSpec} of this permission.</li>
    * <li>if the first {@code URLPattern} in the name of the argument permission matches the first {@code URLPattern} in
    * the {@code URLPatternSpec} of this permission, then every {@code URLPattern} in the {@code URLPatternList} of the
    * {@code URLPatternSpec} of this permission is matched by a {@code URLPattern} in the {@code URLPatternList} of the
    * argument permission.</li>
    * </ul>
    * </p>
    * 
    * <p>
    * {@code URLPattern} matching is performed using the Servlet matching rules where two {@code URL} patterns match if
    * they are related as follows:
    * <ul>
    * <li>their pattern values are {@code String} equivalent, or</li>
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
    * @param spec
    *           the {@code URLPatternSpec} to which this {@code URLPatternSpec} is to be compared.
    * @return {@code true} if this implies spec; {@code false} otherwise.
    */
   boolean implies(URLPatternSpec spec)
   {
      /*
       * The first URLPattern in the name of the argument permission is matched by the first URLPattern in the name of
       * this permission.
       */
      boolean implies = this.urlPattern.matches(spec.urlPattern);
      if (implies)
      {
         /*
          * The first URLPattern in the name of the argument permission is NOT matched by any URLPattern in the
          * URLPatternList of the URLPatternSpec of this permission.
          */
         if (this.urlPatternList != null)
         {
            for (URLPattern p : this.urlPatternList)
            {
               if (p.matches(spec.urlPattern))
                  return false;
            }
         }

         /*
          * If the first URLPattern in the name of the argument permission matches the first URLPattern in the
          * URLPatternSpec of this permission, then every URLPattern in the URLPatternList of the URLPatternSpec of this
          * permission is matched by a URLPattern in the URLPatternList of the argument permission.
          */
         if (this.urlPatternList != null && spec.urlPatternList != null)
         {
            for (URLPattern p : this.urlPatternList)
            {
               boolean hasMatch = false;
               for (URLPattern p2 : spec.urlPatternList)
               {
                  if (p.matches(p2))
                  {
                     hasMatch = true;
                     break;
                  }
               }
               if (hasMatch == false)
                  return false;
            }
         }
      }
      return implies;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#hashCode()
    */
   @Override
   public int hashCode()
   {
      int result = 17;
      result = 37 * result + this.urlPattern.hashCode();
      if (this.urlPatternList != null)
         result = 37 * result + this.urlPatternList.hashCode();
      return result;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#equals(java.lang.Object)
    */
   @Override
   public boolean equals(Object obj)
   {
      if (obj instanceof URLPatternSpec == false)
         return false;
      URLPatternSpec other = (URLPatternSpec) obj;
      if (this.urlPattern.equals(other.urlPattern) == true)
      {
         if (this.urlPatternList == null || this.urlPatternList.equals(other.urlPatternList))
         {
            return true;
         }
      }
      return false;
   }
}
