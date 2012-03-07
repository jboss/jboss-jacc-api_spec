package javax.security.jacc;

import java.util.Set;
import java.util.Map;
import java.util.Collections;
import java.util.HashMap;
import java.security.SecurityPermission;

/**
 * <p>
 * This utility class is used by containers to communicate policy context identifiers and other policy relevant context
 * to {@code Policy} providers. {@code Policy} providers use the policy context identifier to select the subset of
 * policy to apply in access decisions.
 * </p>
 * 
 * <p>
 * The value of a policy context identifier is a {@code String} and each thread has an independently established policy
 * context identifier. A container will establish the thread-scoped value of a policy context identifier by calling the
 * static {@code setContextID} method. The value of a thread-scoped policy context identifier is available (to {@code
 * Policy}) by calling the static {@code getContextID} method.
 * </p>
 * 
 * <p>
 * This class is also used by {@code Policy} providers to request additional thread-scoped policy relevant context
 * objects from the calling container. Containers register container-specific {@code PolicyContext} handlers using the
 * static {@code registerHandler} method. Handler registration is scoped to the class, such that the same handler
 * registrations are active in all thread contexts. Containers may use the static method {@code setHandlerData} to
 * establish a thread-scoped parameter that will be passed to handlers when they are activated by {@code Policy}
 * providers. The static {@code getContext} method is used to activate a handler and obtain the corresponding context
 * object.
 * </p>
 * 
 * <p>
 * The static accessor functions provided by this class allow per-thread policy context values to be established and
 * communicated independent of a common reference to a particular {@code PolicyContext} instance.
 * </p>
 * 
 * <p>
 * The {@code PolicyContext} class may encapsulate static {@code ThreadLocal} instance variables to represent the policy
 * context identifier and handler data values.
 * </p>
 * 
 * <p>
 * The Application server must bundle or install the {@code PolicyContext} class, and the containers of the application
 * server must prevent the methods of the {@code PolicyContext} class from being called from calling contexts that are
 * not authorized to call these methods. With the exception of the {@code getContextID} and {@code getHandlerKeys}
 * methods, containers must restrict and afford access to the methods of the {@code PolicyContext} class to calling
 * contexts trusted by the container to perform container access decisions. The {@code PolicyContext} class may satisfy
 * this requirement (on behalf of its container) by rejecting calls made from an {@code AccessControlContext} that has
 * not been granted the "setPolicy" SecurityPermission, and by ensuring that {@code Policy} providers used to perform
 * container access decisions are granted the "setPolicy" permission.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link PolicyContextHandler}
 */
public final class PolicyContext
{
   private static SecurityPermission setPolicy = new SecurityPermission("setPolicy");

   private static SecurityPermission getPolicy = new SecurityPermission("getPolicy");

   private static ThreadLocal<Object> handlerDataLocal = new ThreadLocal<Object>();

   private static ThreadLocal<String> contextIDLocal = new ThreadLocal<String>();

   private static Map<String, PolicyContextHandler> handlerMap = Collections
         .synchronizedMap(new HashMap<String, PolicyContextHandler>());

   /**
    * <p>
    * This method may be used by a {@code Policy} provider to activate the {@code PolicyContextHandler} registered to
    * the context object key and cause it to return the corresponding policy context object from the container. When
    * this method activates a handler, it passes to the handler the context object key and the handler data associated
    * with the calling thread.
    * </p>
    * 
    * @param key
    *           - a {@code String} that identifies the PolicyContextHandler to activate and the context object to be
    *           acquired from the handler. The value of this parameter must not be null.
    * @return the container and handler specific object containing the desired context. A {@code null} value is returned
    *         if the corresponding handler has been registered, and the value of the corresponding context is null.
    * @throws IllegalArgumentException
    *            - if a {@code PolicyContextHandler} has not been registered for the key or the registered handler no
    *            longer supports the key.
    * @throws SecurityException
    *            - if the calling {@code AccessControlContext} is not authorized by the container to call this method.
    * @throws PolicyContextException
    *            - if an operation by this method on the identified {@code PolicyContextHandler} causes it to throw a
    *            checked exception that is not accounted for in the signature of this method.
    */
   public static Object getContext(String key) throws PolicyContextException
   {
      if (key == null || handlerMap.containsKey(key) == false)
         throw new IllegalArgumentException("No PolicyContextHandler for key=" + key);
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(getPolicy);

      PolicyContextHandler handler = (PolicyContextHandler) handlerMap.get(key);
      if (handler.supports(key) == false)
         throw new IllegalArgumentException("PolicyContextHandler does not support key=" + key);
      Object data = handlerDataLocal.get();
      Object context = handler.getContext(key, data);
      return context;
   }

   /**
    * <p>
    * This static method returns the value of the policy context identifier associated with the thread on which the
    * accessor is called.
    * </p>
    * 
    * @return The {@code String} (or {@code null}) policy context identifier established for the thread. This method
    *         must return the default policy context identifier, {@code null}, if the policy context identifier of the
    *         thread has not been set via {@code setContext} to another value.
    * @throws SecurityException
    *            - if the calling {@code AccessControlContext} is not authorized by the container to call this method.
    *            Containers may choose to authorize calls to this method by any {@code AccessControlContext}.
    */
   public static String getContextID()
   {
      String contextID = (String) contextIDLocal.get();
      return contextID;
   }

   /**
    * <p>
    * This method may be used to obtain the keys that identify the container specific context handlers registered by the
    * container.
    * </p>
    * 
    * @return A {@code Set}, the elements of which, are the {@code String} key values that identify the handlers that
    *         have been registered and therefore may be activated on the {@code PolicyContext}.
    */
   @SuppressWarnings("unchecked")
   public static Set getHandlerKeys()
   {
      return handlerMap.keySet();
   }

   /**
    * <p>
    * Authorization protected method used to register a container specific {@code PolicyContext} handler. A handler may
    * be registered to handle multiple keys, but at any time, at most one handler may be registered for a key.
    * </p>
    * 
    * @param key
    *           - a (case-sensitive) {@code String} that identifies the context object handled by the handler. The value
    *           of this parameter must not be null.
    * @param handler
    *           - an object that implements the {@code PolicyContextHandler} interface. The value of this parameter must
    *           not be null.
    * @param replace
    *           - this boolean value defines the behavior of this method if, when it is called, a {@code
    *           PolicyContextHandler} has already been registered to handle the same key. In that case, and if the value
    *           of this argument is {@code true}, the existing handler is replaced with the argument handler. If the
    *           value of this parameter is false the existing registration is preserved and an exception is thrown.
    * @throws IllegalArgumentException
    *            - if the value of either of the handler or key arguments is null, or the value of the replace argument
    *            is false and a handler with the same key as the argument handler is already registered.
    * @throws SecurityException
    *            - if the calling {@code AccessControlContext} is not authorized by the container to call this method.
    * @throws PolicyContextException
    *            - if an operation by this method on the argument {@code PolicyContextHandler} causes it to throw a
    *            checked exception that is not accounted for in the signature of this method.
    */
   public static void registerHandler(String key, PolicyContextHandler handler, boolean replace)
         throws PolicyContextException
   {
      if (key == null)
         throw new IllegalArgumentException("The key may not be null");
      if (handler == null)
         throw new IllegalArgumentException("The handler may not be null");
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(setPolicy);
      if (replace == false && handlerMap.containsKey(key) == true)
      {
         String msg = "Handler for key=" + key + ", exists, handler: " + handlerMap.get(key);
         throw new IllegalArgumentException(msg);
      }
      handlerMap.put(key, handler);
   }

   /**
    * <p>
    * Authorization protected method used to modify the value of the policy context identifier associated with the
    * thread on which this method is called.
    * </p>
    * 
    * @param contextID
    *           - a {@code String} that represents the value of the policy context identifier to be assigned to the
    *           {@code PolicyContext} for the calling thread. The value null is a legitimate value for this parameter.
    * @throws SecurityException
    *            - if the calling {@code AccessControlContext} is not authorized by the container to call this method.
    */
   public static void setContextID(String contextID)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(setPolicy);
      contextIDLocal.set(contextID);
   }

   /**
    * <p>
    * Authorization protected method that may be used to associate a thread-scoped handler data object with the
    * PolicyContext. The handler data object will be made available to handlers, where it can serve to supply or bind
    * the handler to invocation scoped state within the container.
    * </p>
    * 
    * @param data
    *           - a container-specific object that will be associated with the calling thread and passed to any handler
    *           activated by a {@code Policy} provider (on the thread). The value null is a legitimate value for this
    *           parameter, and is the value that will be used in the activation of handlers if the {@code
    *           setHandlerData} has not been called on the thread.
    * @throws SecurityException
    *            - if the calling {@code AccessControlContext} is not authorized by the container to call this method.
    */
   public static void setHandlerData(Object data)
   {
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(setPolicy);
      handlerDataLocal.set(data);
   }

   /**
    * <p>
    * Private constructor.
    * </p>
    */
   private PolicyContext()
   {
   }
}
