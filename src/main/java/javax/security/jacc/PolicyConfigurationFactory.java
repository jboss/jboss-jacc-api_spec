package javax.security.jacc;

import java.security.Permission;
import java.security.SecurityPermission;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.security.PrivilegedActionException;

/**
 * <p>
 * Abstract factory and finder class for obtaining the instance of the class that implements the
 * PolicyConfigurationFactory of a provider. The factory will be used to instantiate PolicyConfiguration objects that
 * will be used by the deployment tools of the container to create and manage policy contexts within the Policy
 * Provider.
 * </p>
 * 
 * <p>
 * Implementation classes must have a public no argument constructor that may be used to create an operational instance
 * of the factory implementation class.
 * </p>
 * 
 * @author <a href="mailto:scott.stark@jboss.org">Scott Stark</a>
 * @author <a href="mailto:sguilhen@redhat.com">Stefan Guilhen</a>
 * @see {@link Permission}, {@link PolicyConfiguration}, {@link PolicyContextException}
 */
public abstract class PolicyConfigurationFactory
{
   /**
    * The standard name of the system property specifying the JACC PolicyConfigurationFactory implementation class name.
    */
   private static final String FACTORY_PROP = "javax.security.jacc.PolicyConfigurationFactory.provider";

   /** The default PolicyConfigurationFactory implementation */
   private static final String DEFAULT_FACTORY_NAME = "org.jboss.security.jacc.JBossPolicyConfigurationFactory";

   /** The loaded PolicyConfigurationFactory provider */
   private static PolicyConfigurationFactory factory;

   /**
    * <p>
    * This static method uses a system property to find and instantiate (via a public constructor) a provider spe- cific
    * factory implementation class. The name of the provider specific factory implementation class is obtained from the
    * value of the system property,
    * 
    * <pre>
    * javax.security.jacc.PolicyConfigurationFactory.provider.
    * </pre>
    * 
    * </p>
    * 
    * @return the singleton instance of the provider specific PolicyConfigurationFactory implementation class.
    * @throws SecurityException
    *            - when called by an AccessControlContext that has not been granted the “setPolicy” SecurityPermission.
    * @throws ClassNotFoundException
    *            - when the class named by the system property could not be found including because the value of the
    *            system property has not be set.
    * @throws PolicyContextException
    *            - if the implementation throws a checked exception that has not been accounted for by the
    *            getPolicyConfigurationFactory method signature. The exception thrown by the implementation class will
    *            be encapsulated (during construction) in the thrown PolicyContextException
    */
   public static PolicyConfigurationFactory getPolicyConfigurationFactory() throws ClassNotFoundException,
         PolicyContextException
   {
      // Validate the caller permission
      SecurityManager sm = System.getSecurityManager();
      if (sm != null)
         sm.checkPermission(new SecurityPermission("setPolicy"));

      synchronized (PolicyConfigurationFactory.class)
      {
    	  if (factory == null)
    	  {
    		  String factoryName = null;
    		  Class<?> clazz = null;
    		  try
    		  {
    			  LoadAction action = new LoadAction();
    			  try
    			  {
    				  clazz = AccessController.doPrivileged(action);
    				  factoryName = action.getName();
    			  }
    			  catch (PrivilegedActionException ex)
    			  {
    				  factoryName = action.getName();
    				  Exception e = ex.getException();
    				  if (e instanceof ClassNotFoundException)
    					  throw (ClassNotFoundException) e;
    				  else
    					  throw new PolicyContextException("Failure during load of class: " + factoryName, e);
    			  }
    			  factory = (PolicyConfigurationFactory) clazz.newInstance();
    		  }
    		  catch (ClassNotFoundException e)
    		  {
    			  String msg = "Failed to find PolicyConfigurationFactory : " + factoryName;
    			  throw new ClassNotFoundException(msg, e);
    		  }
    		  catch (IllegalAccessException e)
    		  {
    			  String msg = "Unable to access class : " + factoryName;
    			  throw new PolicyContextException(msg, e);
    		  }
    		  catch (InstantiationException e)
    		  {
    			  String msg = "Failed to create instance of: " + factoryName;
    			  throw new PolicyContextException(msg, e);
    		  }
    		  catch (ClassCastException e)
    		  {
    			  StringBuffer msg = new StringBuffer(factoryName + " Is not a PolicyConfigurationFactory, ");
    			  msg.append("PCF.class.CL: " + PolicyConfigurationFactory.class.getClassLoader());
    			  msg.append("\nPCF.class.CS: " + PolicyConfigurationFactory.class.getProtectionDomain().getCodeSource());
    			  msg.append("\nPCF.class.hash: " + System.identityHashCode(PolicyConfigurationFactory.class));
    			  msg.append("\nclazz.CL: " + clazz.getClassLoader());
    			  msg.append("\nclazz.CS: " + clazz.getProtectionDomain().getCodeSource());
    			  msg.append("\nclazz.super.CL: " + clazz.getSuperclass().getClassLoader());
    			  msg.append("\nclazz.super.CS: " + clazz.getSuperclass().getProtectionDomain().getCodeSource());
    			  msg.append("\nclazz.super.hash: " + System.identityHashCode(clazz.getSuperclass()));
    			  ClassCastException cce = new ClassCastException(msg.toString());
    			  cce.initCause(e);
    			  throw cce;
    		  }
    	  }
      }
      return factory;
   }

   /**
    * <p>
    * This method is used to obtain an instance of the provider specific class that implements the PolicyConfiguration
    * interface that corresponds to the identified policy context within the provider. The methods of the
    * PolicyConfiguration interface are used to define the policy statements of the identified policy context.
    * </p>
    * 
    * <p>
    * If at the time of the call, the identified policy context does not exist in the provider, then the policy context
    * will be created in the provider and the Object that implements the context’s PolicyConfiguration Interface will be
    * returned. If the state of the identified context is “deleted” or “inService” it will be transitioned to the “open”
    * state as a result of the call. The states in the lifecycle of a policy context are defined by the
    * PolicyConfiguration interface.
    * </p>
    * 
    * <p>
    * For a given value of policy context identifier, this method must always return the same instance of
    * PolicyConfiguration and there must be at most one actual instance of a PolicyConfiguration with a given policy
    * context identifier (during a process context).
    * </p>
    * 
    * <p>
    * To preserve the invariant that there be at most one PolicyConfiguration object for a given policy context, it may
    * be necessary for this method to be thread safe.
    * </p>
    * 
    * @param contextID
    *           - A String identifying the policy context whose PolicyConfiguration interface is to be returned. The
    *           value passed to this parameter must not be null.
    * @param remove
    *           - A boolean value that establishes whether or not the policy statements and linkages of an existing
    *           policy context are to be removed before its PolicyConfiguration object is returned. If the value passed
    *           to this parameter is true, the policy statements and linkages of an existing policy context will be
    *           removed. If the value is false, they will not be removed.
    * @return an Object that implements the PolicyConfiguration Interface matched to the Policy provider and
    *         corresponding to the identified policy context.
    * @throws SecurityException
    *            - when called by an AccessControlContext that has not been granted the “setPolicy” SecurityPermission.
    * @throws PolicyContextException
    *            - if the implementation throws a checked exception that has not been accounted for by the
    *            getPolicyConfiguration method signature. The exception thrown by the implementation class will be
    *            encapsulated (during construction) in the thrown PolicyContextException.
    */
   public abstract PolicyConfiguration getPolicyConfiguration(String contextID, boolean remove)
         throws PolicyContextException;

   /**
    * <p>
    * This method determines if the identified policy context exists with state “inService” in the Policy provider
    * associated with the factory.
    * </p>
    * 
    * @param contextID
    *           - A string identifying a policy context.
    * @return true if the identified policy context exists within the provider and its state is “inService”, false
    *         otherwise.
    * @throws SecurityException
    *            - when called by an AccessControlContext that has not been granted the “setPolicy” SecurityPermission.
    * @throws PolicyContextException
    *            - if the implementation throws a checked exception that has not been accounted for by the inService
    *            method signature. The exception thrown by the implementation class will be encapsulated (during
    *            construction) in the thrown PolicyContextException.
    */
   public abstract boolean inService(String contextID) throws PolicyContextException;

   /**
    * <p>
    * A PrivilegedExceptionAction that looks up the class name identified by the {@code
    * javax.security.jacc.PolicyConfigurationFactory.provider} system property and loads the class using the thread
    * context class loader.
    * </p>
    */
   private static class LoadAction implements PrivilegedExceptionAction<Class<?>>
   {
      private String name;

      public String getName()
      {
         return name;
      }

      public Class<?> run() throws Exception
      {
         name = System.getProperty(FACTORY_PROP);
         if (name == null)
         {
            // Use the default factory implementation.
            name = DEFAULT_FACTORY_NAME;
         }
         ClassLoader[] cls = new ClassLoader[] { PolicyConfigurationFactory.class.getClassLoader(), // JACC classes (not always on TCCL [modular env])
        		 Thread.currentThread().getContextClassLoader(), // User defined classes
                 ClassLoader.getSystemClassLoader() // System loader, usually has app class path
         };
         ClassNotFoundException e = null;
         for (ClassLoader cl : cls)
         {
             if (cl == null)
                 continue;

             try
             {
                 return cl.loadClass(name);
             }
             catch (ClassNotFoundException ce)
             {
                 e = ce;
             }
         }
         throw e != null ? e : new ClassNotFoundException(name);
      }
   }
}
