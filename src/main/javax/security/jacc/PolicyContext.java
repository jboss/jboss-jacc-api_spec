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

import java.util.Set;
import java.util.Map;
import java.util.Collections;
import java.util.HashMap;
import java.security.SecurityPermission;

/** This utility class is used by containers to communicate policy context
 * identifiers and other policy relevant context to Policy providers. Policy
 * providers use the policy context identifier to select the subset of policy
 * to apply in access decisions.
 * 
 * The value of a policy context identifier is a String and each thread has an
 * independently established policy context identifier. A container will
 * establish the thread-scoped value of a policy context identifier by calling
 * the static setContextID method. The value of a thread-scoped policy context
 * identifier is available (to Policy) by calling the static getContextID method.
 * 
 * This class is also used by Policy providers to request additional
 * thread-scoped policy relevant context objects from the calling container.
 * Containers register container-specific PolicyContext handlers using the
 * static registerHandler method. Handler registration is scoped to the class,
 * such that the same handler registrations are active in all thread contexts.
 * Containers may use the static method setHandlerData to establish a
 * thread-scoped parameter that will be passed to handlers when they are
 * activated by Policy providers. The static getContext method is used to
 * activate a handler and obtain the corresponding context object.
 * 
 * The static accessor functions provided by this class allow per-thread policy
 * context values to be established and communicated independent of a common
 * reference to a particular PolicyContext instance.
 * 
 * The PolicyContext class may encapsulate static ThreadLocal instance variables
 * to represent the policy context identifier and handler data values.
 * 
 * The Application server must bundle or install the PolicyContext class, and
 * the containers of the application server must prevent the methods of the
 * PolicyContext class from being called from calling contexts that are not
 * authorized to call these methods. With the exception of the getContextID
 * and GetHandlerKeys methods, containers must restrict and afford access to
 * the methods of the PolicyContext class to calling contexts trusted by the
 * container to perform container access decisions. The PolicyContext class may
 * satisfy this requirement (on behalf of its container) by rejecting calls made
 * from an AccessControlContext that has not been granted the "setPolicy"
 * SecurityPermission, and by ensuring that Policy providers used to perform
 * container access decisions are granted the "setPolicy" permission.
 * 
 * @see http://java.sun.com/j2ee/1.4/docs/api/
 * 
 * @author Scott.Stark@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public final class PolicyContext
{
   private static SecurityPermission setPolicy = new SecurityPermission("setPolicy");
   private static SecurityPermission getPolicy = new SecurityPermission("getPolicy");
   private static ThreadLocal handlerDataLocal = new ThreadLocal();
   private static ThreadLocal contextIDLocal = new ThreadLocal();
   private static Map handlerMap = Collections.synchronizedMap(new HashMap());

   /** This method may be used by a Policy provider to activate the
    * PolicyContextHandler registered to the context object key and cause it to
    * return the corresponding policy context object from the container. When
    * this method activates a handler, it passes to the handler the context
    * object key and the handler data associated with the calling thread.
    * 
    * @param key - a non-null String that identifies the PolicyContextHandler to
    * activate as well as the context object to be acquired from the handler.
    * @return the container and handler specific object containing the desired
    * context. A null value is returned if the corresponding handler has been
    * registered, and the value of the corresponding context is null.
    * @throws IllegalArgumentException - if a PolicyContextHandler has not been
    * registered for the key or the registered handler no longer supports the key.
    * @throws SecurityException - if the caller does not have the
    * SecurityPermission("getPolicy") permission.
    * @throws PolicyContextException - if an operation by this method on the
    * identified PolicyContextHandler causes it to throw a checked exception
    * that is not accounted for in the signature of this method.
    */
   public static Object getContext(String key)
      throws PolicyContextException
   {
      if( key == null || handlerMap.containsKey(key) == false )
         throw new IllegalArgumentException("No PolicyContextHandler for key="+key);
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(getPolicy);

      PolicyContextHandler handler = (PolicyContextHandler) handlerMap.get(key);
      if( handler.supports(key) == false )
         throw new IllegalArgumentException("PolicyContextHandler does not support key="+key);
      Object data = handlerDataLocal.get();
      Object context = handler.getContext(key, data);
      return context;
   }

   /** This method returns the value of the policy context identifier associated
    * with the thread on which the accessor is called.
    * 
    * @return the possibly null policy context identifier established for the
    * thread. This method must return the default policy context identifier,
    * null, if the policy context identifier of the thread has not been set via
    * setContext to another value.
    */ 
   public static String getContextID()
   {
      String contextID = (String) contextIDLocal.get();
      return contextID;
   }

   /** This method may be used to obtain the keys that identify the container
    * specific context handlers registered by the container.
    * 
    * @return A Set, the elements of which, are the String key values that
    * identify the handlers that have been registered and therefore may be
    * activated on the PolicyContext
    */ 
   public static Set getHandlerKeys()
   {
      return handlerMap.keySet();
   }

   /** Authorization protected method used to register a container specific
    * PolicyContext handler. A handler may be registered to handle multiple keys,
    * but at any time, at most one handler may be registered for a key.
    * 
    * @param key - a case-sensitive, non-null String that identifies the context
    * object handled by the handler.
    * @param handler - an non-null object that implements the PolicyContextHandler
    * interface.
    * @param replace - this boolean value defines the behavior of this method
    * if, when it is called, a PolicyContextHandler has already been registered
    * to handle the same key. In that case, and if the value of this argument is
    * true, the existing handler is replaced with the argument handler. If the
    * value of this parameter is false the existing registration is preserved
    * and an exception is thrown.
    * 
    * @throws IllegalArgumentException - if the value of either of the handler
    * or key arguments is null, or the value of the replace argument is false
    * and a handler with the same key as the argument handler is already
    * registered.
    * @throws SecurityException - if the caller does not have the
    * SecurityPermission("setPolicy") permission.
    * @throws PolicyContextException - if an operation by this method on the
    * argument PolicyContextHandler causes it to throw a checked exception that
    * is not accounted for in the signature of this method.
    */ 
   public static void registerHandler(String key, PolicyContextHandler handler,
      boolean replace)
      throws PolicyContextException
   {
      if( key == null )
         throw new IllegalArgumentException("The key may not be null");
      if( handler == null )
         throw new IllegalArgumentException("The handler may not be null");
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(setPolicy);
      if( replace == false && handlerMap.containsKey(key) == true )
      {
         String msg = "Handler for key="+key+", exists, handler: "+handlerMap.get(key);
         throw new IllegalArgumentException(msg);
      }

      handlerMap.put(key, handler);
   }

   /** Authorization protected method used to modify the value of the policy
    * context identifier associated with the thread on which this method is
    * called
    * 
    * @param contextID - a String that represents the value of the policy
    * context identifier to be assigned to the PolicyContext for the calling
    * thread. The value null  is a legitimate value for this parameter.
    * @throws SecurityException - if the caller does not have the
    * SecurityPermission("setPolicy") permission.
    * 
    */
   public static void setContextID(String contextID)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(setPolicy);
      contextIDLocal.set(contextID);
   }

   /** Authorization protected method that may be used to associate a
    * thread-scoped handler data object with the PolicyContext. The handler data
    * object will be made available to handlers, where it can serve to supply or
    * bind the handler to invocation scoped state within the container.
    * 
    * @param data - a container-specific object that will be associated with the
    * calling thread and passed to any handler activated by a Policy provider
    * (on the thread). The value null is a legitimate value for this parameter,
    * and is the value that will be used in the activation of handlers if the
    * setHandlerData has not been called on the thread.
    * @throws SecurityException - if the caller does not have the
    * SecurityPermission("setPolicy") permission.
    */
   public static void setHandlerData(Object data)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(setPolicy);
      handlerDataLocal.set(data);
   }

   private PolicyContext()
   {
   }
}
