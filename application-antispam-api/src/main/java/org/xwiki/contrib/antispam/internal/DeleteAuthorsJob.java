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
package org.xwiki.contrib.antispam.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.job.AbstractJob;
import org.xwiki.job.DefaultJobStatus;
import org.xwiki.model.EntityType;
import org.xwiki.model.ModelContext;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Delete authors in a job.
 *
 * @version $Id$
 */
@Component
@Named(DeleteAuthorsJob.TYPE)
public class DeleteAuthorsJob extends AbstractJob<DeleteAuthorRequest, DefaultJobStatus<DeleteAuthorRequest>>
{
    public static final String TYPE = "cleanAuthors";

    @Inject
    private AuthorizationManager authorizationManager;

    @Inject
    private ModelContext modelContext;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Override
    public String getType()
    {
        return TYPE;
    }

    @Override
    protected void runInternal() throws Exception
    {
        Collection<DocumentReference> authorReferences = this.request.getAuthorReferences();

        this.progressManager.pushLevelProgress(authorReferences.size(), this);

        try {
            // Protection. If the user has Admin rights at the level of the wiki, then don't remove it!
            List<DocumentReference> filteredAuthorReferences = new ArrayList<>();
            for (DocumentReference authorReference : authorReferences) {
                if (!this.authorizationManager.hasAccess(Right.ADMIN, authorReference,
                    this.modelContext.getCurrentEntityReference().extractReference(EntityType.WIKI)))
                {
                    this.progressManager.startStep(this);
                    if (request.isVerbose()) {
                        this.logger.info("Filtering out user [{}] since it has Admin rights on the wiki...",
                            authorReference);
                    }
                    filteredAuthorReferences.add(authorReference);
                }
            }

            clean(() -> {
                XWikiContext xcontext = this.contextProvider.get();
                XWiki xwiki = xcontext.getWiki();
                if (request.isVerbose()) {
                    this.logger.info("Starting removal of [{}] inactive users...", filteredAuthorReferences.size());
                }
                for (DocumentReference authorReference : filteredAuthorReferences) {
                    this.progressManager.startStep(this);
                    if (this.status.isCanceled()) {
                        break;
                    }
                    if (request.isVerbose()) {
                        this.logger.info("User [{}] is being removed...", authorReference);
                    }
                    deleteUser(authorReference, xwiki, xcontext);
                    if (request.isVerbose()) {
                        this.logger.info("User [{}] has been removed.", authorReference);
                    }
                }
            });
        } finally {
            this.progressManager.popLevelProgress(this);
        }
    }

    private void deleteUser(DocumentReference authorReference, XWiki xwiki, XWikiContext xcontext)
        throws AntiSpamException
    {
        try {
            XWikiDocument userDocument = xwiki.getDocument(authorReference, xcontext);
            if (!userDocument.isNew()) {
                xwiki.deleteAllDocuments(userDocument, false, xcontext);
            }
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to delete user [%s]", authorReference), e);
        }
    }

    private void clean(CleaningExecutor executor) throws AntiSpamException
    {
        // Make sure we don't generate Activity Stream events since we don't want spam cleaning to end up in the
        // Activity as it would swamp all other activities and hide it under its volume.
        boolean skipEventStream = this.request.skipEventStreamRecording();
        if (skipEventStream) {
            this.observationManager.notify(new AntiSpamBeginFoldEvent(), null, null);
        }
        try {
            executor.clean();
        } finally {
            if (skipEventStream) {
                this.observationManager.notify(new AntiSpamEndFoldEvent(), null, null);
            }
        }
    }

    private interface CleaningExecutor
    {
        void clean() throws AntiSpamException;
    }
}
