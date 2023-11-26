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

import java.util.Collection;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.antispam.SpamCheckerProtectionManager;
import org.xwiki.model.EntityType;
import org.xwiki.model.ModelContext;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.user.group.GroupException;
import org.xwiki.user.group.GroupManager;
import org.xwiki.user.group.WikiTarget;

/**
 * Implementation getting the list known users and groups from wiki pages.
 *
 * @version $Id$
 * @since 1.9
 */
@Component
@Singleton
public class DefaultSimpleSpamCheckerProtectionManager implements SpamCheckerProtectionManager
{
    @Inject
    private Logger logger;

    @Inject
    private SpamCheckerModel model;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> referenceResolver;

    @Inject
    private GroupManager groupManager;

    @Inject
    private ModelContext modelContext;

    @Inject
    private AuthorizationManager authorizationManager;

    @Override
    public boolean isProtectedUser(DocumentReference authorReference, DocumentReference documentReference)
    {
        boolean isProtectedUser = false;
        try {
            // Is the author a known user?
            // Is the author a member of a known group?
            // Does the author have Admin rights on the passed entity?
            isProtectedUser = isImportantAuthor(authorReference, documentReference)
                || isKnownUser(authorReference)
                || isKnownGroup(authorReference);
        } catch (GroupException e) {
            this.logger.warn("Failed to get groups for [{}]. Assuming that the user is not a protected user.",
                authorReference, e);
        }
        return isProtectedUser;
    }

    private boolean isImportantAuthor(DocumentReference authorReference, DocumentReference documentReference)
    {
        WikiReference wikiReference =
            (WikiReference) this.modelContext.getCurrentEntityReference().extractReference(EntityType.WIKI);
        boolean isImportantAuthor = this.authorizationManager.hasAccess(Right.ADMIN, authorReference, wikiReference);
        if (documentReference != null) {
            isImportantAuthor = isImportantAuthor || this.authorizationManager.hasAccess(Right.ADMIN, authorReference,
                documentReference);
        }
        return isImportantAuthor;
    }

    private boolean isKnownUser(DocumentReference authorReference)
    {
        boolean isKnownUser = false;
        for (String knownUser : this.model.getKnownUsers()) {
            if (authorReference.equals(this.referenceResolver.resolve(knownUser))) {
                isKnownUser = true;
                break;
            }
        }
        return isKnownUser;
    }

    private boolean isKnownGroup(DocumentReference authorReference) throws GroupException
    {
        boolean isKnownGroup = false;
        // The list of groups the passed author belongs to, in the current wiki and in the wiki where the author is
        // defined.
        Collection<DocumentReference> groups = this.groupManager.getGroups(authorReference,
            WikiTarget.ENTITY_AND_CURRENT, true);
        for (String knownGroup : this.model.getKnownGroups()) {
            if (groups.contains(this.referenceResolver.resolve(knownGroup))) {
                isKnownGroup = true;
                break;
            }
        }
        return isKnownGroup;
    }
}
