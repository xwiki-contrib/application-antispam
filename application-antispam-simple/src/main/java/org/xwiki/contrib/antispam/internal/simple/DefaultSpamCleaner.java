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

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.solr.client.solrj.response.QueryResponse;
import org.apache.solr.common.SolrDocument;
import org.suigeneris.jrcs.rcs.Version;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.component.util.DefaultParameterizedType;
import org.xwiki.contrib.antispam.MatchingReference;
import org.xwiki.contrib.antispam.SpamCheckerProtectionManager;
import org.xwiki.contrib.antispam.SpamCleaner;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.contrib.antispam.internal.AntiSpamBeginFoldEvent;
import org.xwiki.contrib.antispam.internal.AntiSpamEndFoldEvent;
import org.xwiki.eventstream.Event;
import org.xwiki.eventstream.EventSearchResult;
import org.xwiki.eventstream.EventStore;
import org.xwiki.eventstream.query.SimpleEventQuery;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.query.solr.internal.SolrQueryExecutor;
import org.xwiki.search.solr.internal.api.FieldUtils;
import org.xwiki.search.solr.internal.api.SolrIndexer;
import org.xwiki.user.group.GroupException;
import org.xwiki.user.group.GroupManager;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.criteria.api.XWikiCriteriaService;
import com.xpn.xwiki.criteria.impl.PeriodFactory;
import com.xpn.xwiki.criteria.impl.RangeFactory;
import com.xpn.xwiki.criteria.impl.RevisionCriteria;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.doc.XWikiDocumentArchive;
import com.xpn.xwiki.doc.rcs.XWikiRCSNodeInfo;

@Component
@Singleton
public class DefaultSpamCleaner implements SpamCleaner
{
    @Inject
    private QueryManager queryManager;

    @Inject
    @Named("context")
    private Provider<ComponentManager> contextComponentManagerProvider;

    @Inject
    private SolrIndexer solrIndexer;

    @Inject
    @Named("user")
    private DocumentReferenceResolver<String> userDocumentReferenceResolver;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private ObservationManager observationManager;

    @Inject
    private EventStore eventStore;

    @Inject
    private SpamCheckerModel model;

    @Inject
    private GroupManager groupManager;

    @Inject
    private SpamCheckerProtectionManager protectionManager;

    @Override
    public List<MatchingReference> getMatchingDocuments(String solrQueryString, int nb, int offset)
        throws AntiSpamException
    {
        List<MatchingReference> matchingReferences = new ArrayList<>();

        try {
            waitForSolrIndexing();

            Query query = this.queryManager.createQuery(solrQueryString + " AND -id:xwiki\\:AntiSpam.*_*",
                SolrQueryExecutor.SOLR);
            query.setLimit(nb);
            query.setOffset(offset);
            query.bindValue("fq", "type:DOCUMENT");
            QueryResponse queryResponse = (QueryResponse) query.execute().get(0);
            ComponentManager componentManager = this.contextComponentManagerProvider.get();
            for (SolrDocument solrDocument : queryResponse.getResults()) {
                MatchingReference matchingReference = new MatchingReference(
                    resolveSolrDocument(solrDocument, componentManager),
                    this.userDocumentReferenceResolver.resolve((String) solrDocument.get(FieldUtils.AUTHOR)));
                matchingReferences.add(matchingReference);
            }
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to find documents matching [%s]", solrQueryString), e);
        }

        return matchingReferences;
    }

    @Override
    public List<DocumentReference> getDocumentsForAuthor(DocumentReference authorReference, int nb, int offset)
        throws AntiSpamException
    {
        List<DocumentReference> references = new ArrayList<>();

        try {
            waitForSolrIndexing();

            Query query = this.queryManager.createQuery("*:* AND -id:xwiki\\:AntiSpam.*_*", SolrQueryExecutor.SOLR);
            query.setLimit(nb);
            query.setOffset(offset);
            String authorAsString = this.entityReferenceSerializer.serialize(authorReference);
            query.bindValue("fq", String.format("type:DOCUMENT AND (author:\"%s\" OR creator:\"%s\")",
                authorAsString, authorAsString));
            QueryResponse queryResponse = (QueryResponse) query.execute().get(0);
            ComponentManager componentManager = this.contextComponentManagerProvider.get();
            for (SolrDocument solrDocument : queryResponse.getResults()) {
                references.add(resolveSolrDocument(solrDocument, componentManager));
            }
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to find documents for author [%s]", authorReference), e);
        }

        return references;
    }

    @Override
    public void cleanDocument(DocumentReference documentReference, Collection<DocumentReference> authorReferences,
        boolean skipActivityStream) throws AntiSpamException
    {
        // Extra safety: exclude protected users (admins, etc) from the author reference list since we don't want to
        // delete edits by important users by mistake. For example, it's easy for an admin to edit a document in which
        // someone had added a spam keyword (without seeing it), and then when cleaning up, the last author would be
        // associated with a content with spam and thus will have its edit removed.
        List<DocumentReference> filteredAuthorReferences = new ArrayList<>();
        for (DocumentReference authorReference : authorReferences) {
            if (!this.protectionManager.isProtectedUser(authorReference, documentReference)) {
                filteredAuthorReferences.add(authorReference);
            }
        }

        clean(skipActivityStream, () -> {
            try {
                // (Performance optimization) Check if the document has more than 1 revision and if not then simply
                // delete the document. This is because getting the full revision list could take a lot of time if
                // a document has a lot of revisions.
                XWikiContext xcontext = this.contextProvider.get();
                XWiki xwiki = xcontext.getWiki();
                XWikiDocument document = xwiki.getDocument(documentReference, xcontext);
                if (hasSeveralRevisions(document, xwiki, xcontext)) {
                    deleteRevisions(filteredAuthorReferences, document, xwiki, xcontext);
                } else {
                    // Simply delete the document from all its translations but don't put it in the trash since we don't
                    // want spam to go in the trash
                    // Note: We perform an extra check to be sure we're deleting the right document...
                    if (filteredAuthorReferences.contains(document.getAuthorReference())) {
                        xwiki.deleteAllDocuments(document, false, xcontext);
                    }
                }
            } catch (Exception e) {
                throw new AntiSpamException(String.format(
                    "Failed to clean document [%s] of changes made by author [%s]",
                    documentReference, filteredAuthorReferences), e);
            }
        });
    }

    @Override
    public List<DocumentReference> getInactiveAuthors(int elapsedDays, boolean cleanAuthorsWithAvatars, int count)
        throws AntiSpamException
    {
        try {
            return getAuthorsWithActivity(getInactiveAuthorCandidates(elapsedDays, cleanAuthorsWithAvatars), count);
        } catch (Exception e) {
            throw new AntiSpamException("Failed to find inactive users", e);
        }
    }

    @Override
    public Set<DocumentReference> getKnownUserReferences() throws AntiSpamException
    {
        Set<DocumentReference> knownUserReferences = new HashSet<>();

        // Get all users from the known user list.
        List<String> knownUsers = this.model.getKnownUsers();
        knownUsers.add("xwiki:XWiki.superadmin");
        for (String authorReferenceString : knownUsers) {
            knownUserReferences.add(this.userDocumentReferenceResolver.resolve(authorReferenceString));
        }

        // Get all users from the known group list.
        List<String> knownGroups = this.model.getKnownGroups();
        knownGroups.add("xwiki:XWiki.XWikiAdminGroup");
        for (String groupReferenceString : knownGroups) {
            // Find all users from that group
            DocumentReference groupReference = this.userDocumentReferenceResolver.resolve(groupReferenceString);
            try {
                knownUserReferences.addAll(this.groupManager.getMembers(groupReference, true));
            } catch (GroupException e) {
                throw new AntiSpamException(
                    String.format("Failure to get users from group [%s]", groupReferenceString), e);
            }
        }

        return knownUserReferences;
    }

    private List<DocumentReference> getAuthorsWithActivity(List<DocumentReference> authorReferences, int count)
        throws Exception
    {
        List<DocumentReference> filteredAuthorReferences = new ArrayList<>();
        int counter = 0;
        for (DocumentReference authorReference : authorReferences) {
            // Has the author done at least one change in the whole wiki or wiki farm?
            SimpleEventQuery query = new SimpleEventQuery(0, 1);
            query.eq(Event.FIELD_USER, this.entityReferenceSerializer.serialize(authorReference));
            try (EventSearchResult result = this.eventStore.search(query)) {
                if (result.getTotalHits() == 0) {
                    if (!this.protectionManager.isProtectedUser(authorReference, null)) {
                        filteredAuthorReferences.add(authorReference);
                        counter++;
                    }
                }
            }
            if (counter == count) {
                break;
            }
        }
        return filteredAuthorReferences;
    }

    private List<DocumentReference> getInactiveAuthorCandidates(int elapsedDays, boolean cleanAuthorsWithAvatars)
        throws Exception
    {
        List<DocumentReference> candidates = new ArrayList<>();
        String avatarClause = cleanAuthorsWithAvatars ? "" : "and user.avatar = ''";
        Query query = this.queryManager.createQuery("from doc.object(XWiki.XWikiUsers) as user "
                + "where doc.date < :date "
                + avatarClause
                + "and doc.fullName not in (select distinct obj2.name from BaseObject as obj2 where "
                + "obj2.className = 'XWiki.OIDC.ConsentClass')",
            Query.XWQL);
        query.bindValue("date", getDateMinusDays(elapsedDays));
        for (String authorReferenceString : query.<String>execute()) {
            candidates.add(this.userDocumentReferenceResolver.resolve(authorReferenceString));
        }

        return candidates;
    }

    private Date getDateMinusDays(int elapsedDays)
    {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.DATE, -elapsedDays);
        return calendar.getTime();
    }

    private void clean(boolean skipActivityStream, CleaningExecutor executor) throws AntiSpamException
    {
        // Make sure we don't generate Activity Stream events since we don't want spam cleaning to end up in the
        // Activity as it would swamp all other activities and hide it under its volume.
        if (skipActivityStream) {
            this.observationManager.notify(new AntiSpamBeginFoldEvent(), null, null);
        }
        try {
            executor.clean();
        } finally {
            if (skipActivityStream) {
                this.observationManager.notify(new AntiSpamEndFoldEvent(), null, null);
            }
        }
    }

    private void deleteRevisions(Collection<DocumentReference> authorReferences, XWikiDocument document, XWiki xwiki,
        XWikiContext xcontext) throws Exception
    {
        // Start with the oldest revision (for performance reason as we don't have to make the last revision's content
        // be the current document's content at each delete).
        Version[] versions = document.getRevisions(xcontext);

        // A document can have 0 revisions (if they've all been deleted)
        if (versions.length == 0) {
            return;
        }

        for (int i = 0; i < versions.length; i++) {
            // Get the revision author
            String revision = versions[i].toString();
            XWikiRCSNodeInfo revisionInfo = document.getRevisionInfo(revision, xcontext);
            DocumentReference revisionAuthor = this.userDocumentReferenceResolver.resolve(revisionInfo.getAuthor());
            if (authorReferences.contains(revisionAuthor)) {
                deleteRevision(versions[i], document, xwiki, xcontext);
            }
        }
    }

    /**
     * This method should be provided by XWiki's platform, see http://jira.xwiki.org/browse/XWIKI-13036
     * The code below has been copied from DeleteVersionsAction.
     */
    private void deleteRevision(Version version, XWikiDocument document, XWiki xwiki, XWikiContext xcontext)
        throws Exception
    {
        XWikiDocumentArchive documentArchive = document.getDocumentArchive();
        documentArchive.removeVersions(version, version, xcontext);
        xwiki.getVersioningStore().saveXWikiDocArchive(documentArchive, true, xcontext);
        document.setDocumentArchive(documentArchive);

        // Is this the last remaining version? If so, then recycle the document.
        if (documentArchive.getLatestVersion() == null) {
            xwiki.deleteAllDocuments(document, false, xcontext);
        } else {
            // There are still some versions left.
            // If we delete the most recent (current) version, then rollback to latest undeleted version.
            if (!document.getRCSVersion().equals(documentArchive.getLatestVersion())) {
                XWikiDocument newdoc = documentArchive.loadDocument(documentArchive.getLatestVersion(), xcontext);
                // Reset the document reference, since the one taken from the archive might be wrong (old name from
                // before a rename)
                newdoc.setDocumentReference(document.getDocumentReference());
                // Make sure we don't create a new rev!
                newdoc.setMetaDataDirty(false);
                newdoc.addXObjectsToRemoveFromVersion(document);
                // Note: make sure we have events sent so that the SOLR module (for example) can reindex the document's
                // content.
                xwiki.saveDocument(newdoc, xcontext);
            }
        }
    }

    private boolean hasSeveralRevisions(XWikiDocument document, XWiki xwiki, XWikiContext xcontext)
        throws Exception
    {
        XWikiCriteriaService criteriaService = xwiki.getCriteriaService(xcontext);
        RevisionCriteria revisionCriteria = criteriaService.getRevisionCriteriaFactory().createRevisionCriteria(
            PeriodFactory.createMaximumPeriod(), true);
        revisionCriteria.setRange(RangeFactory.createTailRange(2));
        return document.getRevisions(revisionCriteria, xcontext).size() > 1;
    }

    private DocumentReference resolveSolrDocument(SolrDocument solrDocument, ComponentManager componentManager)
        throws ComponentLookupException
    {
        DocumentReference resultDocumentReference;

        // Starting with 7.2+ (Nested Spaces) SolrDocument will contain an escaped list of spaces,
        // whereas post 7.2 it contains an unescaped space name.
        // Starting with 7.2+ there's a Solr Document Reference Resolver available which should be used.
        Type solrResolverType = new DefaultParameterizedType(null, DocumentReferenceResolver.class, SolrDocument.class);
        if (componentManager.hasComponent(solrResolverType)) {
            DocumentReferenceResolver<SolrDocument> solrResolver = componentManager.getInstance(solrResolverType);
            resultDocumentReference = solrResolver.resolve(solrDocument);
        } else {
            resultDocumentReference = new DocumentReference((String) solrDocument.get(FieldUtils.WIKI),
                (String) solrDocument.get(FieldUtils.SPACE), (String) solrDocument.get(FieldUtils.NAME));
        }
        return resultDocumentReference;
    }

    private void waitForSolrIndexing() throws Exception
    {
        // Important: Make sure the Solr indexing queue is empty since otherwise a document could be in the indexing
        // queue. For example after some of the antispam tool removed its last revision which was containing some
        // spam and the search would wrongly match that document and return it!
        while (this.solrIndexer.getQueueSize() > 0) {
            Thread.sleep(100L);
        }
    }

    private interface CleaningExecutor
    {
        void clean() throws AntiSpamException;
    }
}
