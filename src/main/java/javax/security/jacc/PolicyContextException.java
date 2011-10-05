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
 * This checked exception is thrown by the policy context and configuration classes.
 * 
 * @see http://java.sun.com/j2ee/1.4/docs/api/
 * @see javax.security.jacc.PolicyConfiguration
 * @see javax.security.jacc.PolicyConfigurationFactory
 * @see javax.security.jacc.PolicyContext
 * 
 * @author Scott.Stark@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public class PolicyContextException extends Exception {
    public PolicyContextException() {
    }

    public PolicyContextException(String msg) {
        super(msg);
    }

    public PolicyContextException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public PolicyContextException(Throwable cause) {
        super(cause);
    }
}
