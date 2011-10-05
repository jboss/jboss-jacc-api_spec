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
 * JACC interface which defines the methods that must be implemented by handlers that are to be registered and activated by
 * PolicyContexts
 * 
 * @see http://java.sun.com/j2ee/1.4/docs/api/
 * 
 * @author Scott.Stark@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public interface PolicyContextHandler {
    /**
     * Used by the PolicyContext class to activate the handler and obtain from it the context object identified by the given
     * key. In addition to the key, the handler will be activated with the handler data value associated within the
     * PolicyContext class with the thread on which the call to this method is made.
     * 
     * @param key - a non-null key indicating which context to return.
     * @param data - the possiblye null handler data Object associated with the thread on which the call to this method has been
     *        made.
     * @return The container and handler specific Object containing the desired context. A null value may be returned if the
     *         value of the corresponding context is null.
     * @throws PolicyContextException
     */
    public Object getContext(String key, Object data) throws PolicyContextException;

    /**
     * Get the keys identifying the context objects supported by this handlers getContext(String, Object) method. The value of
     * each key supported by a handler must be a non-null String value.
     * 
     * @return the list of supported context object keys.
     * @throws PolicyContextException
     */
    public String[] getKeys() throws PolicyContextException;

    /**
     * Query the handler to see if its getContext(String, Object) method supports the given key.
     * 
     * @param key - the context object key to check.
     * @return true if the key is supported, false otherwise
     * @throws PolicyContextException
     */
    public boolean supports(String key) throws PolicyContextException;
}
