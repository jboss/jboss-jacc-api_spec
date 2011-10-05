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

/**
 * The representation of a URLPattern in the WebResourcePermission and WebUserDataPermission URLPatternSpecs.
 * 
 * @author Scott.Stark@jboss.org
 * @version $Revison:$
 */
class URLPattern {
    /** the '/' pattern */
    static final int DEFAULT = 0;
    /** the '/*' pattern */
    static final int THE_PATH_PREFIX = 1;
    /** a '/.../*' pattern */
    static final int PATH_PREFIX = 2;
    /** a '*.xxx' pattern */
    static final int EXTENSION = 3;
    /** an exact pattern */
    static final int EXACT = 4;

    private String pattern;
    private String ext;
    private int length;
    private int type = -1;

    URLPattern(String pattern) {
        this.pattern = pattern;
        length = pattern.length();
        if (pattern.equals("/"))
            type = DEFAULT;
        else if (pattern.startsWith("/*"))
            type = THE_PATH_PREFIX;
        else if (length > 0 && pattern.charAt(0) == '/' && pattern.endsWith("/*"))
            type = PATH_PREFIX;
        else if (pattern.startsWith("*.")) {
            type = EXTENSION;
            ext = pattern.substring(1);
        } else
            type = EXACT;
    }

    /**
     * The matching rules from the WebResourcePermission implies:
     * 
     * 1. their pattern values are String equivalent, or 2. this pattern is the path-prefix pattern "/*", or 3. this pattern is
     * a path-prefix pattern (that is, it starts with "/" and ends with "/*") and the argument pattern starts with the substring
     * of this pattern, minus its last 2 characters, and the next character of the argument pattern, if there is one, is "/", or
     * 4. this pattern is an extension pattern (that is, it starts with "*.") and the argument pattern ends with this pattern,
     * or 5. the reference pattern is the special default pattern, "/", which matches all argument patterns.
     */
    boolean matches(URLPattern url) {
        return matches(url.pattern);
    }

    boolean matches(String urlPattern) {
        // 2 or 5
        if (type == DEFAULT || type == THE_PATH_PREFIX)
            return true;

        // 4, extension pattern
        if (type == EXTENSION && urlPattern.endsWith(ext))
            return true;

        // 3. a path-prefix pattern
        if (type == PATH_PREFIX) {
            if (urlPattern.regionMatches(0, pattern, 0, length - 2)) {
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

    String getPattern() {
        return pattern;
    }

    boolean isDefault() {
        return type == DEFAULT;
    }

    boolean isExact() {
        return type == EXACT;
    }

    boolean isExtension() {
        return type == EXTENSION;
    }

    boolean isPrefix() {
        return type == THE_PATH_PREFIX || type == PATH_PREFIX;
    }

    public int hashCode() {
        return pattern.hashCode();
    }

    boolean equals(URLPattern p) {
        boolean equals = type == p.type;
        if (equals) {
            equals = pattern.equals(p.pattern);
        }
        return equals;
    }

}
