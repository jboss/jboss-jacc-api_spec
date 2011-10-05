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

import java.security.Permission;
import java.security.PermissionCollection;

/**
 * The methods of this interface are used by containers to create policy statements in a Policy provider. An object that
 * implements the PolicyConfiguration interface provides the policy statement configuration interface for a corresponding policy
 * context within the corresponding Policy provider.
 * 
 * The life cycle of a policy context is defined by three states; "open", "inService", and "deleted". A policy context is in one
 * of these three states.
 * 
 * A policy context in the "open" state is in the process of being configured, and may be operated on by any of the methods of
 * the PolicyConfiguration interface. A policy context in the "open" state must not be assimilated at
 * <code>Policy.refresh</code> into the policy statements used by the Policy provider in performing its access decisions. In
 * order for the policy statements of a policy context to be assimilated by the associated provider, the policy context must be
 * in the "inService" state. A policy context in the "open" state is transitioned to the "inService" state by calling the commit
 * method.
 * 
 * A policy context in the "inService" state is available for assimilation into the policy statements being used to perform
 * access decisions by the associated Policy provider. Providers assimilate policy contexts containing policy statements when
 * the refresh method of the provider is called. When a provider's refresh method is called, it must assimilate only those
 * policy contexts whose state is "inService" and it must ensure that the policy statements put into service for each policy
 * context are only those defined in the context at the time of the call to refresh. A policy context in the "inService" state
 * is not available for additional configuration and may be returned to the "open" state by calling the getPolicyConfiguration
 * method of the PolicyConfigurationFactory.
 * 
 * A policy context in the "deleted" state is neither available for configuration, nor is it available for assimilation into the
 * Provider. A policy context whose state is "deleted" may be reclaimed for subsequent processing by calling the
 * getPolicyConfiguration method of the associated PolicyConfigurationFactory. A "deleted" policy context is transitioned to the
 * "open" state when it it returned as a result of a call to getPolicyConfiguration.
 * 
 * The following table captures the correspondence between the policy context life cycle and the methods of the
 * PolicyConfiguration interface. The rightmost 3 columns of the table correspond to the PolicyConfiguration state identified at
 * the head of the column. The values in the cells of these columns indicate the next state resulting from a call to the method
 * identifed in the leftmost column of the corresponding row, or that calling the method is unsupported in the state represented
 * by the column (in which case the state will remain unchanged).
 * 
 * <table border="1" width="90%" nosave="" align="center">
 * <caption>PolicyConfiguration State Table</caption>
 * <tr>
 * <th valign="middle" rowspan="2" colspan="1" align="center">
 * <font size="-2">Method</font></th>
 * <th valign="top" rowspan="1" colspan="3" align="center">
 * <font size="-2">Current State to Next State</font></th>
 * </tr>
 * 
 * <tr>
 * <th width="25%" align="center"><font size="-2">deleted</font></th>
 * <th width="12%" align="center"><font size="-2">open</font></th>
 * <th width="25%" align="center"><font size="-2">inService</font></th>
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">addToExcludedPolicy</font></td>
 * 
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center">
 * <font size="-2">open</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * </tr>
 * 
 * <tr>
 * <td width="28%"><font size="-2">addToRole</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center">
 * <font size="-2">open</font></td>
 * <td width="25%" align="center">
 * 
 * <font size="-2">Unsupported Operation</font></td>
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">addToUncheckedPolicy</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center">
 * 
 * <font size="-2">open</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">commit</font></td>
 * <td width="25%" align="center">
 * 
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center">
 * <font size="-2">inService</font></td>
 * <td width="25%" align="center">
 * <font size="-2">inService</font></td>
 * </tr>
 * <tr>
 * 
 * <td width="28%"><font size="-2">delete</font></td>
 * <td width="25%" align="center">
 * <font size="-2">deleted</font></td>
 * <td width="12%" align="center">
 * <font size="-2">deleted</font></td>
 * <td width="25%" align="center">
 * <font size="-2">deleted</font></td>
 * 
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">getContextID</font></td>
 * <td width="25%" align="center">
 * <font size="-2">deleted</font></td>
 * <td width="12%" align="center">
 * <font size="-2">open</font></td>
 * 
 * <td width="25%" align="center">
 * <font size="-2">inService</font></td>
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">inService</font></td>
 * <td width="25%" align="center">
 * <font size="-2">deleted</font></td>
 * 
 * <td width="12%" align="center">
 * <font size="-2">open</font></td>
 * <td width="25%" align="center">
 * <font size="-2">inService</font></td>
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">linkConfiguration</font></td>
 * 
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center">
 * <font size="-2">open</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * </tr>
 * 
 * <tr>
 * <td width="28%"><font size="-2">removeExcludedPolicy</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center"><font size="-2"> open</font></td>
 * <td width="25%" align="center">
 * 
 * <font size="-2">Unsupported Operation</font></td>
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">removeRole</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center">
 * 
 * <font size="-2">open</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * </tr>
 * <tr>
 * <td width="28%"><font size="-2">removeUncheckedPolicy</font></td>
 * <td width="25%" align="center">
 * 
 * <font size="-2">Unsupported Operation</font></td>
 * <td width="12%" align="center">
 * <font size="-2">open</font></td>
 * <td width="25%" align="center">
 * <font size="-2">Unsupported Operation</font></td>
 * </tr>
 * </table>
 * 
 * For a provider implementation to be compatible with multi-threaded environments, it may be necessary to synchronize the
 * refresh method of the provider with the methods of its PolicyConfiguration interface and with the getPolicyConfiguration and
 * inService methods of its PolicyConfigurationFactory.
 * 
 * @see http://java.sun.com/j2ee/1.4/docs/api/
 * 
 * @author Scott.Stark@jboss.org
 * @author Ron Monzillo, Gary Ellison (javadoc)
 * @version $Revision$
 */
public interface PolicyConfiguration {
    /**
     * Adds a single excluded permission to the PolicyConfiguration.
     * 
     * @param permission
     * @throws PolicyContextException
     */
    public void addToExcludedPolicy(Permission permission) throws PolicyContextException;

    /**
     * Adds a collection of excluded permissions to the PolicyConfiguration
     * 
     * @param permissions
     * @throws PolicyContextException
     */
    public void addToExcludedPolicy(PermissionCollection permissions) throws PolicyContextException;

    /**
     * Add a single permission to a named role in the PolicyConfiguration. If the named Role does not exist in the
     * PolicyConfiguration, it is created as a result of the call to this function.
     * 
     * @param roleName
     * @param permission
     * @throws PolicyContextException
     */
    public void addToRole(String roleName, Permission permission) throws PolicyContextException;

    /**
     * Add permissions to a named role in the PolicyConfiguration. If the named Role does not exist in the PolicyConfiguration,
     * it is created as a result of the call to this function.
     * 
     * @param roleName
     * @param permissions
     * @throws PolicyContextException
     */
    public void addToRole(String roleName, PermissionCollection permissions) throws PolicyContextException;

    /**
     * Add a single unchecked permission to the PolicyConfiguration.
     * 
     * @param permission
     * @throws PolicyContextException
     */
    public void addToUncheckedPolicy(Permission permission) throws PolicyContextException;

    /**
     * Add unchecked permissions to the PolicyConfiguration.
     * 
     * @param permissions
     * @throws PolicyContextException
     */
    public void addToUncheckedPolicy(PermissionCollection permissions) throws PolicyContextException;

    /**
     * This method is used to set to "inService" the state of the policy context whose interface is this PolicyConfiguration
     * Object. Only those policy contexts whose state is "inService" will be included in the policy contexts processed by the
     * Policy.refresh method. A policy context whose state is "inService" may be returned to the "open" state by calling the
     * getPolicyConfiguration method of the PolicyConfiguration factory with the policy context identifier of the policy
     * context.
     * 
     * When the state of a policy context is "inService", calling any method other than commit, delete, getContextID, or
     * inService on its PolicyConfiguration Object will cause an UnsupportedOperationException to be thrown.
     * 
     * @throws SecurityException - when the caller does not have a SecurityPermission("setPolicy") permission.
     * @throws UnsupportedOperationException - if the state of the policy context whose interface is this PolicyConfiguration
     *         Object is "deleted" when this method is called.
     * @throws PolicyContextException - if the implementation throws a checked exception that has not been accounted for by the
     *         commit method signature.
     */
    public void commit() throws PolicyContextException;

    /**
     * Causes all policy statements to be deleted from this PolicyConfiguration and sets its internal state such that calling
     * any method, other than delete, getContextID, or inService on the PolicyConfiguration will be rejected and cause an
     * UnsupportedOperationException to be thrown.
     * 
     * This operation has no affect on any linked PolicyConfigurations other than removing any links involving the deleted
     * PolicyConfiguration.
     * 
     * @throws SecurityException - when the caller does not have a SecurityPermission("setPolicy") permission.
     * @throws PolicyContextException
     */
    public void delete() throws PolicyContextException;

    /**
     * This method returns this object's policy context identifier.
     * 
     * @return this object's policy context identifier.
     * 
     * @throws SecurityException - when the caller does not have a SecurityPermission("setPolicy") permission.
     * @throws PolicyContextException
     */
    public String getContextID() throws PolicyContextException;

    /**
     * This method is used to determine if the policy context whose interface is this PolicyConfiguration Object is in the
     * "inService" state.
     * 
     * @return true if the state of the associated policy context is "inService", false otherwise.
     * @throws PolicyContextException
     */
    public boolean inService() throws PolicyContextException;

    /**
     * Creates a relationship between this configuration and another such that they share the same principal-to-role mappings.
     * PolicyConfigurations are linked to apply a common principal-to-role mapping to multiple seperately manageable
     * PolicyConfigurations, as is required when an application is composed of multiple modules.
     * 
     * @param link - a reference to a different PolicyConfiguration than this PolicyConfiguration. The relationship formed by
     *        this method is symetric, transitive and idempotent. If the argument PolicyConfiguration does not have a different
     *        Policy context identifier than this PolicyConfiguration no relationship is formed, and an IllegalArgumentException
     *        is thrown.
     * 
     * @throws SecurityException - when the caller does not have a SecurityPermission("setPolicy") permission.
     * @throws IllegalArgumentException - if called with an argument PolicyConfiguration whose Policy context is equivalent to
     *         that of this PolicyConfiguration.
     * @throws PolicyContextException
     */
    public void linkConfiguration(PolicyConfiguration link) throws PolicyContextException;

    /**
     * Used to remove any excluded policy statements from this PolicyConfiguration
     * 
     * @throws SecurityException - when the caller does not have a SecurityPermission("setPolicy") permission.
     * @throws UnsupportedOperationException - if the state of the policy context whose interface is this PolicyConfiguration
     *         Object is "deleted" or "inService" when this method is called.
     * @throws PolicyContextException
     */
    public void removeExcludedPolicy() throws PolicyContextException;

    /**
     * Used to remove a role and all its permissions from this PolicyConfiguration.
     * 
     * @param roleName - the name of the Role to remove from this PolicyConfiguration.
     * 
     * @throws SecurityException - when the caller does not have a SecurityPermission("setPolicy") permission.
     * @throws UnsupportedOperationException - if the state of the policy context whose interface is this PolicyConfiguration
     *         Object is "deleted" or "inService" when this method is called.
     * @throws PolicyContextException
     */
    public void removeRole(String roleName) throws PolicyContextException;

    /**
     * Used to remove any unchecked policy statements from this PolicyConfiguration.
     * 
     * @throws SecurityException - when the caller does not have a SecurityPermission("setPolicy") permission.
     * @throws UnsupportedOperationException - if the state of the policy context whose interface is this PolicyConfiguration
     *         Object is "deleted" or "inService" when this method is called.
     * @throws PolicyContextException
     */
    public void removeUncheckedPolicy() throws PolicyContextException;
}
