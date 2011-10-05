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

import java.util.HashSet;
import java.util.StringTokenizer;
import java.util.Iterator;

/**
 * Encapsulation of the URLPatternSpec defined in the WebResourcePermission and WebUserDataPermission.
 * 
 * @link WebResourcePermission(String, String)
 * @link WebUserDataPermission(String, String)
 * 
 * @author Scott.Stark@jboss.org
 * @version $Revison:$
 */
class URLPatternSpec {
    /** The first or only URLPattern in the spec */
    URLPattern urlPattern;
    /** */
    HashSet urlPatternList;

    /**
     * The spec contains a URLPatternSpec that identifies the web resources to which the permissions applies. The syntax of a
     * URLPatternSpec is as follows:
     * 
     * URLPatternList ::= URLPattern | URLPatternList colon URLPattern URLPatternSpec ::= null | URLPattern | URLPattern colon
     * URLPatternList
     * 
     * A null URLPatternSpec is translated to the default URLPattern, "/", by the permission constructor. The empty string is an
     * exact URLPattern, and may occur anywhere in a URLPatternSpec that an exact URLPattern may occur. The first URLPattern in
     * a URLPatternSpec may be any of the pattern types, exact, path-prefix, extension, or default as defined in the Java
     * Servlet Specification). When a URLPatternSpec includes a URLPatternList, the patterns of the URLPatternList identify the
     * resources to which the permission does NOT apply and depend on the pattern type and value of the first pattern as
     * follows:
     * 
     * - No pattern may exist in the URLPatternList that matches the first pattern. - If the first pattern is a path-prefix
     * pattern, only exact patterns matched by the first pattern and path-prefix patterns matched by, but different from, the
     * first pattern may occur in the URLPatternList. - If the first pattern is an extension pattern, only exact patterns that
     * are matched by the first pattern and path-prefix patterns may occur in the URLPatternList. - If the first pattern is the
     * default pattern, "/", any pattern except the default pattern may occur in the URLPatternList. - If the first pattern is
     * an exact pattern a URLPatternList must not be present in the URLPatternSpec.
     * 
     * @param spec
     */
    URLPatternSpec(String spec) {
        if (spec == null)
            urlPattern = new URLPattern("/");
        else if (spec.indexOf(':') > 0) {
            StringTokenizer tokenizer = new StringTokenizer(spec, ":");
            urlPatternList = new HashSet();
            while (tokenizer.hasMoreTokens()) {
                String pattern = tokenizer.nextToken();
                URLPattern p = new URLPattern(pattern);
                if (urlPattern == null)
                    urlPattern = p;
                else {
                    // Enforce the constraints
                    if (p.matches(urlPattern)) {
                        /*
                         * No pattern may exist in the URLPatternList that matches the first pattern.
                         */
                        String msg = "1: URLPatternList item: " + pattern + " matches: " + urlPattern.getPattern();
                        throw new IllegalArgumentException(msg);
                    } else if (urlPattern.isPrefix()) {
                        /*
                         * If the first pattern is a path-prefix pattern, only exact patterns matched by the first pattern and
                         * path-prefix patterns matched by, but different from, the first pattern may occur in the
                         * URLPatternList.
                         */
                        if (p.isPrefix() == false && p.isExact() == false) {
                            String msg = "2: URLPatternList item: " + pattern + " is not an exact or prefix pattern";
                            throw new IllegalArgumentException(msg);
                        }
                    } else if (urlPattern.isExtension()) {
                        /*
                         * If the first pattern is an extension pattern, only exact patterns that are matched by the first
                         * pattern and path-prefix patterns may occur in the URLPatternList.
                         */
                        if (p.isPrefix() == false && p.isExact() == false) {
                            String msg = "3: URLPatternList item: " + pattern + " is not an exact or prefix pattern";
                            throw new IllegalArgumentException(msg);
                        }
                    } else if (urlPattern.isDefault()) {
                        /*
                         * If the first pattern is the default pattern, "/", any pattern except the default pattern may occur in
                         * the URLPatternList.
                         */
                        if (p.isDefault()) {
                            String msg = "4: URLPatternList item: " + pattern + " cannot be the default pattern";
                            throw new IllegalArgumentException(msg);
                        }
                    } else if (urlPattern.isExact()) {
                        /*
                         * If the first pattern is an exact pattern a URLPatternList must not be present in the URLPatternSpec.
                         */
                        String msg = "5: URLPatternList item: " + pattern + " is not allowed in an exact pattern";
                        throw new IllegalArgumentException(msg);
                    }
                    urlPatternList.add(p);
                }
            }
        } else {
            urlPattern = new URLPattern(spec);
        }
    }

    /**
     * Perform the permission URLPattern matching - The first URLPattern in the name of the argument permission is matched by
     * the first URLPattern in the name of this permission. - The first URLPattern in the name of the argument permission is NOT
     * matched by any URLPattern in the URLPatternList of the URLPatternSpec of this permission. - If the first URLPattern in
     * the name of the argument permission matches the first URLPattern in the URLPatternSpec of this permission, then every
     * URLPattern in the URLPatternList of the URLPatternSpec of this permission is matched by a URLPattern in the
     * URLPatternList of the argument permission.
     * 
     * URLPattern matching is performed using the Servlet matching rules where two URL patterns match if they are related as
     * follows: - their pattern values are String equivalent, or - this pattern is the path-prefix pattern "/*", or - this
     * pattern is a path-prefix pattern (that is, it starts with "/" and ends with "/*") and the argument pattern starts with
     * the substring of this pattern, minus its last 2 characters, and the next character of the argument pattern, if there is
     * one, is "/", or - this pattern is an extension pattern (that is, it starts with "*.") and the argument pattern ends with
     * this pattern, or - the reference pattern is the special default pattern, "/", which matches all argument patterns.
     * 
     * All of the comparisons described above are case sensitive.
     * 
     * @param spec
     * @return true if this implies spec, false otherwise
     */
    boolean implies(URLPatternSpec spec) {
        /*
         * The first URLPattern in the name of the argument permission is matched by the first URLPattern in the name of this
         * permission.
         */
        boolean implies = urlPattern.matches(spec.urlPattern);
        if (implies) {
            /*
             * The first URLPattern in the name of the argument permission is NOT matched by any URLPattern in the
             * URLPatternList of the URLPatternSpec of this permission.
             */
            if (urlPatternList != null) {
                Iterator iter = urlPatternList.iterator();
                while (iter.hasNext()) {
                    URLPattern p = (URLPattern) iter.next();
                    if (p.matches(spec.urlPattern))
                        return false;
                }
            }

            /*
             * If the first URLPattern in the name of the argument permission matches the first URLPattern in the URLPatternSpec
             * of this permission, then every URLPattern in the URLPatternList of the URLPatternSpec of this permission is
             * matched by a URLPattern in the URLPatternList of the argument permission.
             */
            if (urlPatternList != null && spec.urlPatternList != null) {
                Iterator iter = urlPatternList.iterator();
                while (iter.hasNext()) {
                    URLPattern p = (URLPattern) iter.next();
                    boolean hasMatch = false;
                    Iterator iter2 = spec.urlPatternList.iterator();
                    while (iter2.hasNext()) {
                        URLPattern p2 = (URLPattern) iter2.next();
                        if (p.matches(p2)) {
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

    int hash() {
        int hashCode = urlPattern.hashCode();
        if (urlPatternList != null)
            hashCode += urlPatternList.hashCode();
        return hashCode;
    }

    boolean equals(URLPatternSpec spec) {
        if (urlPattern.equals(spec.urlPattern) == true) {
            if (urlPatternList == null || urlPatternList.equals(spec.urlPatternList)) {
                return true;
            }
        }

        return false;
    }
}
