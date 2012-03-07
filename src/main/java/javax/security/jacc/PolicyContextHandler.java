package javax.security.jacc;

/**
 * <p>
 * This interface defines the methods that must be implemented by handlers that are to be registered and activated by
 * the {@code PolicyContext} class. {@code The PolicyContext} class provides methods for containers to register and
 * activate container-specific {@code PolicyContext} handlers. {@code Policy} providers use the {@code PolicyContext}
 * class to activate handlers to obtain (from the container) additional policy relevant context to apply in their access
 * decisions. All handlers registered and activated via the {@code PolicyContext} class must implement the {@code
 * PolicyContextHandler} interface.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 */
public interface PolicyContextHandler
{
   /**
    * <p>
    * This public method is used by the {@code PolicyContext} class to activate the handler and obtain from it the
    * context object identified by the (case-sensitive) key. In addition to the key, the handler will be activated with
    * the handler data value associated within the {@code PolicyContext} class with the thread on which the call to this
    * method is made.
    * </p>
    * 
    * <p>
    * Note that the policy context identifier associated with a thread is available to the handler by calling {@code
    * PolicyContext.getContextID()}.
    * </p>
    * 
    * @param key
    *           - a {@code String} that identifies the context object to be returned by the handler. The value of this
    *           parameter must not be null.
    * @param data
    *           - the handler data {@code Object} associated with the thread on which the call to this method has been
    *           made. Note that the value passed through this parameter may be {@code null}.
    * @return The container and handler specific {@code Object} containing the desired context. A {@code null} value may
    *         be returned if the value of the corresponding context is {@code null}.
    * @throws PolicyContextException
    *            - if the implementation throws a checked exception that has not been accounted for by the method
    *            signature. The exception thrown by the implementation class will be encapsulated (during construction)
    *            in the thrown {@code PolicyContextException}.
    */
   public Object getContext(String key, Object data) throws PolicyContextException;

   /**
    * <p>
    * This public method returns the keys identifying the context objects supported by the handler. The value of each
    * key supported by a handler must be a non-null {@code String} value.
    * </p>
    * 
    * @return an array containing {@code String} values identifying the context objects supported by the handler. The
    *         array must not contain duplicate key values. In the unlikely case that the Handler supports no keys, the
    *         handler must return a zero length array. The value null must never be returned by this method.
    * @throws PolicyContextException
    *            - if the implementation throws a checked exception that has not been accounted for by the method
    *            signature. The exception thrown by the implementation class will be encapsulated (during construction)
    *            in the thrown {@code PolicyContextException}.
    */
   public String[] getKeys() throws PolicyContextException;

   /**
    * <p>
    * This public method returns a boolean result indicating whether or not the handler supports the context object
    * identified by the (case-sensitive) key value.
    * </p>
    * 
    * @param key
    *           - a {@code String} value identifying a context object that could be supported by the handler. The value
    *           of this parameter must not be null.
    * @return a boolean indicating whether or not the context object corresponding to the argument key is handled by the
    *         handler.
    * @throws PolicyContextException
    *            - if the implementation throws a checked exception that has not been accounted for by the method
    *            signature. The exception thrown by the implementation class will be encapsulated (during construction)
    *            in the thrown {@code PolicyContextException}.
    */
   public boolean supports(String key) throws PolicyContextException;
}
