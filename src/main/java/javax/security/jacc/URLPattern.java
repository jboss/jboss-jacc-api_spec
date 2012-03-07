package javax.security.jacc;

/**
 * <p>
 * The representation of a <b>URLPattern</b> in the {@code WebResourcePermission} and {@code WebUserDataPermission}
 * <b>URLPatternSpecs</b>.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link WebResourcePermission}, {@link WebUserDataPermission}
 */
class URLPattern
{
   private enum PatternType {
      /** the '/' pattern */
      DEFAULT,
      /** the '/*' pattern */
      THE_PATH_PREFIX,
      /** a '/.../*' pattern */
      PATH_PREFIX,
      /** a '*.xxx' pattern */
      EXTENSION,
      /** an exact pattern */
      EXACT
   };

   private String pattern;

   private String ext;

   private int length;

   private PatternType type;

   /**
    * <p>
    * Creates a {@code URLPattern} instance from the specified pattern {@code String}.
    * </p>
    * 
    * @param pattern
    *           the pattern {@code String}.
    */
   URLPattern(String pattern)
   {
      this.pattern = pattern;
      length = pattern.length();
      if (pattern.equals("/"))
         type = PatternType.DEFAULT;
      else if (pattern.startsWith("/*"))
         type = PatternType.THE_PATH_PREFIX;
      else if (length > 0 && pattern.charAt(0) == '/' && pattern.endsWith("/*"))
         type = PatternType.PATH_PREFIX;
      else if (pattern.startsWith("*."))
      {
         type = PatternType.EXTENSION;
         ext = pattern.substring(1);
      }
      else
         type = PatternType.EXACT;
   }

   /**
    * <p>
    * Checks if this pattern matches the specified {@code URLPattern}.
    * </p>
    * 
    * <p>
    * The matching rules from the {@code WebResourcePermission#implies}:
    * <ol>
    * <li>their pattern values are {@code String} equivalent, or</li>
    * <li>this pattern is the path-prefix pattern "/*", or</li>
    * <li>this pattern is a path-prefix pattern (that is, it starts with "/" and ends with "/*") and the argument
    * pattern starts with the substring of this pattern, minus its last 2 characters, and the next character of the
    * argument pattern, if there is one, is "/", or</li>
    * <li>this pattern is an extension pattern (that is, it starts with "*.") and the argument pattern ends with this
    * pattern, or 5. the reference pattern is the special default pattern, "/", which matches all argument patterns.</li>
    * </ol>
    * </p>
    * 
    * @param url
    *           the {@code URLPattern} instance to which this pattern is to be matched.
    * @return {@code true} if this pattern matches the specified {@code URLPattern}; {@code false} otherwise.
    */
   boolean matches(URLPattern url)
   {
      return matches(url.pattern);
   }

   /**
    * <p>
    * Checks if this pattern matches the specified pattern String.
    * </p>
    * 
    * <p>
    * The matching rules from the {@code WebResourcePermission#implies}:
    * <ol>
    * <li>their pattern values are {@code String} equivalent, or</li>
    * <li>this pattern is the path-prefix pattern "/*", or</li>
    * <li>this pattern is a path-prefix pattern (that is, it starts with "/" and ends with "/*") and the argument
    * pattern starts with the substring of this pattern, minus its last 2 characters, and the next character of the
    * argument pattern, if there is one, is "/", or</li>
    * <li>this pattern is an extension pattern (that is, it starts with "*.") and the argument pattern ends with this
    * pattern, or 5. the reference pattern is the special default pattern, "/", which matches all argument patterns.</li>
    * </ol>
    * </p>
    * 
    * @param urlPattern
    *           a {@code String} representing the pattern to which this pattern is to be matched.
    * @return {@code true} if this pattern matches the specified {@code URLPattern}; {@code false} otherwise.
    */
   boolean matches(String urlPattern)
   {
      // 2 or 5
      if (type == PatternType.DEFAULT || type == PatternType.THE_PATH_PREFIX)
         return true;

      // 4, extension pattern
      if (type == PatternType.EXTENSION && urlPattern.endsWith(ext))
         return true;

      // 3. a path-prefix pattern
      if (type == PatternType.PATH_PREFIX)
      {
         if (urlPattern.regionMatches(0, pattern, 0, length - 2))
         {
            int last = length - 2;
            if (urlPattern.length() > last && urlPattern.charAt(last) != '/')
               return false;
            return true;
         }
         return false;
      }

      // 1. pattern values are String equivalent for exact pattern
      if (pattern.equals(urlPattern))
         return true;

      return false;
   }

   /**
    * <p>
    * Obtains the {@code String} representation of this pattern.
    * </p>
    * 
    * @return this pattern's {@code String} representation.
    */
   String getPattern()
   {
      return this.pattern;
   }

   /**
    * <p>
    * Checks if this pattern is a default (i.e. '/') pattern.
    * </p>
    * 
    * @return {@code true} if this is a default pattern; {@code false} otherwise.
    */
   boolean isDefault()
   {
      return this.type == PatternType.DEFAULT;
   }

   /**
    * <p>
    * Checks if this pattern is an exact pattern.
    * </p>
    * 
    * @return {@code true} if this is an exact pattern; {@code false} otherwise.
    */
   boolean isExact()
   {
      return this.type == PatternType.EXACT;
   }

   /**
    * <p>
    * Checks if this pattern is an extension (i.e. '*.xxx') pattern.
    * </p>
    * 
    * @return {@code true} if this is an extension pattern; {@code false} otherwise.
    */
   boolean isExtension()
   {
      return this.type == PatternType.EXTENSION;
   }

   /**
    * <p>
    * Checks if this pattern is a prefix (i.e. '/*' or '/.../*') pattern.
    * </p>
    * 
    * @return {@code true} if this is a prefix pattern; {@code false} otherwise.
    */
   boolean isPrefix()
   {
      return this.type == PatternType.THE_PATH_PREFIX || this.type == PatternType.PATH_PREFIX;
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#hashCode()
    */
   @Override
   public int hashCode()
   {
      return this.pattern.hashCode();
   }

   /*
    * (non-Javadoc)
    * 
    * @see java.lang.Object#equals(java.lang.Object)
    */
   @Override
   public boolean equals(Object o)
   {
      if (o instanceof URLPattern == false)
         return false;
      URLPattern pattern = (URLPattern) o;
      boolean equals = this.type == pattern.type;
      if (equals)
      {
         equals = this.pattern.equals(pattern.pattern);
      }
      return equals;
   }

}
