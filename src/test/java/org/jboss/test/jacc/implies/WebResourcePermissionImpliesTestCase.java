/*
 * JBoss, Home of Professional Open Source. Copyright 2010, Red Hat Middleware
 * LLC, and individual contributors as indicated by the @author tags. See the
 * copyright.txt file in the distribution for a full listing of individual
 * contributors.
 *
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package org.jboss.test.jacc.implies;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import javax.security.jacc.WebResourcePermission;

import org.junit.Test;

/**
 * Unit test the implies for {@code WebResourcePermission}
 * @author anil saldhana
 */
public class WebResourcePermissionImpliesTestCase {

    @Test
    public void testImplies() throws Exception {
        WebResourcePermission w1 = new WebResourcePermission("/", "GET");
        WebResourcePermission w2 = new WebResourcePermission("/", "GET");

        assertTrue(w1.implies(w2));

        w1 = new WebResourcePermission("/", "POST");
        w2 = new WebResourcePermission("/", "POST");

        assertTrue(w1.implies(w2));
        
        w1 = new WebResourcePermission("/now/", "POST");
        w2 = new WebResourcePermission("/anil/*", "POST");

        assertFalse(w1.implies(w2));
        assertFalse(w2.implies(w1));

        w1 = new WebResourcePermission("/", "GET,POST");
        w2 = new WebResourcePermission("/", "GET,POST");

        assertTrue(w1.implies(w2));
        
        w1 = new WebResourcePermission("/", "!GET,POST");
        w2 = new WebResourcePermission("/", "!GET,POST");

        assertTrue(w1.implies(w2));

        w1 = new WebResourcePermission("/", "!GET");
        w2 = new WebResourcePermission("/", "!GET");

        assertTrue(w1.implies(w2));

        w1 = new WebResourcePermission("/", "!GET");
        w2 = new WebResourcePermission("/", "!GET,POST");

        assertFalse(w1.implies(w2));
        
        w1 = new WebResourcePermission("/", "!GET");
        w2 = new WebResourcePermission("/", (String)null);

        assertFalse(w1.implies(w2));
    }
}