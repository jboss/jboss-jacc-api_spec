package javax.security.jacc;

/**
 * <p>
 * This checked exception is thrown by implementations of the {@code javax.security.jacc.PolicyConfiguration} interface,
 * the {@code javax.security.jacc.PolicyConfigurationFactory} abstract class, the {@code
 * javax.security.jacc.PolicyContext} utility class, and implementations of the {@code
 * javax.security.jacc.PolicyContextException} interface.
 * </p>
 * 
 * <p>
 * This exception is used by javax.security.jacc implementation classes to re-throw checked exceptions occurring within
 * an implementation that are not declared by the interface or class being implemented.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link Exception}, {@link PolicyConfiguration}, {@link PolicyConfigurationFactory}, {@link PolicyContext},
 *      {@link PolicyContextHandler}
 */
public class PolicyContextException extends Exception
{
   private static final long serialVersionUID = 3925692572777572935L;

   /**
    * <p>
    * Constructs a new PolicyContextException with null as its detail message. describing the cause of the exception.
    * </p>
    */
   public PolicyContextException()
   {
   }

   /**
    * <p>
    * Constructs a new {@code PolicyContextException} with the specified detail message.
    * </p>
    * 
    * @param msg
    *           - a {@code String} containing a detail message describing the cause of the exception.
    */
   public PolicyContextException(String msg)
   {
      super(msg);
   }

   /**
    * <p>
    * Constructs a new {@code PolicyContextException} with the specified detail message and cause. The cause will be
    * encapsulated in the constructed exception.
    * </p>
    * 
    * @param msg
    *           - a {@code String} containing a detail message describing the cause of the exception.
    * @param cause
    *           - the {@code Throwable} that is “causing” this exception to be constructed. A null value is permitted,
    *           and the value passed through this parameter may subsequently be retrieved by calling {@code getCause()}
    *           on the constructed exception.
    */
   public PolicyContextException(String msg, Throwable cause)
   {
      super(msg, cause);
   }

   /**
    * <p>
    * Constructs a new {@code PolicyContextException} with the specified cause. The cause will be encapsulated in the
    * constructed exception.
    * </p>
    * 
    * @param cause
    *           - the {@code Throwable} that is “causing” this exception to be constructed. A null value is permitted,
    *           and the value passed through this parameter may subsequently be retrieved by calling {@code getCause()}
    *           on the constructed exception.
    */
   public PolicyContextException(Throwable cause)
   {
      super(cause);
   }
}
