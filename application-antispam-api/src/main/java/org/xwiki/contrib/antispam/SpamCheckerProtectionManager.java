/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
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
package org.xwiki.contrib.antispam;

import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;

/**
 * Performs verification checks for the antispam features.
 *
 * @since 1.9
 * @version $Id$
 */
@Role
public interface SpamCheckerProtectionManager
{
    /**
     * Verifies if the passed author is a protected user, i.e. either it belongs to the list of known users, or it
     * belongs to a known group, or it has Admin rights on the passed entity and for the current wiki.
     *
     * @param authorReference the reference of the author to check
     * @param documentReference the reference to the document on which to check for Admin rights. Can be null, in
     *        which case, only Admin rights on the passed wiki will be checked
     * @return true if the author is a protected user, false otherwise
     */
    boolean isProtectedUser(DocumentReference authorReference, DocumentReference documentReference);
}
