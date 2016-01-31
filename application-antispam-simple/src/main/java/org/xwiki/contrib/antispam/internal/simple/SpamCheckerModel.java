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
package org.xwiki.contrib.antispam.internal.simple;

import java.util.List;

import org.xwiki.component.annotation.Role;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.model.reference.DocumentReference;

@Role
public interface SpamCheckerModel
{
    List<String> getSpamAddresses() throws AntiSpamException;

    boolean isSpamAddressDocument(DocumentReference reference);

    List<String> getSpamKeywords() throws AntiSpamException;

    boolean isSpamKeywordDocument(DocumentReference reference);

    boolean isDisabledUserDocument(DocumentReference reference);

    void logSpamAddress(String ip) throws AntiSpamException;

    void logDisabledUser(DocumentReference authorReference) throws AntiSpamException;

    void disableUser(DocumentReference authorReference) throws AntiSpamException;

    boolean iSpamCheckingActive();
}
