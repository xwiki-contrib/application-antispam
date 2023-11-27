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
package org.xwiki.contrib.antispam.script;

import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.contrib.antispam.MatchingReference;
import org.xwiki.contrib.antispam.SpamChecker;
import org.xwiki.contrib.antispam.SpamCheckerProtectionManager;
import org.xwiki.contrib.antispam.SpamCleaner;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.contrib.antispam.internal.DeleteAuthorRequest;
import org.xwiki.contrib.antispam.internal.DeleteAuthorsJob;
import org.xwiki.eventstream.Event;
import org.xwiki.eventstream.EventQuery;
import org.xwiki.eventstream.EventSearchResult;
import org.xwiki.eventstream.EventStore;
import org.xwiki.eventstream.EventStreamException;
import org.xwiki.eventstream.query.SimpleEventQuery;
import org.xwiki.job.Job;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.api.Document;
import com.xpn.xwiki.util.Programming;

/**
 * Script service for the AntiSpam application.
 *
 * @version $Id$
 */
@Component
@Named("antispam")
@Singleton
public class AntiSpamScriptService implements ScriptService
{
    @Inject
    private Logger logger;

    @Inject
    private SpamCleaner cleaner;

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private ContextualAuthorizationManager authorizationManager;

    @Inject
    private JobExecutor jobExecutor;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private EventStore eventStore;

    @Inject
    private SpamCheckerProtectionManager protectionManager;

    /**
     * See {@link SpamCleaner#getMatchingDocuments(String, int, int)}.
     *
     * @param solrQueryString the solr query string to use to search for matching documents
     * @param nb the number of matching documents to return
     * @param offset the start position in the full list of matching documents
     */
    @Programming
    public List<MatchingReference> getMatchingDocuments(String solrQueryString, int nb, int offset)
        throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.cleaner.getMatchingDocuments(solrQueryString, nb, offset);
    }

    /**
     * @param matchingReferences the list of matching references from which to extract the document reference list
     * @return the list of all document references extracted from the passed matching references parameter
     */
    @Programming
    public Set<DocumentReference> getLastAuthorReferences(Collection<MatchingReference> matchingReferences)
        throws AntiSpamException
    {
        checkForProgrammingRights();
        Set<DocumentReference> lastAuthorReferences = new HashSet<>();
        for (MatchingReference matchingReference : matchingReferences) {
            // Remove null author references (meaning the guest user AFAIK) since that would cause some NPE down the
            // line when it's used (unless the calling code checks for it, but best to remove it for safety,
            // especially as we don't care about cleaning guest user ;)).
            if (matchingReference != null) {
                lastAuthorReferences.add(matchingReference.getLastAuthorReference());
            }
        }
        return lastAuthorReferences;
    }

    /**
     * See {@link SpamCleaner#cleanDocument(DocumentReference, Collection, boolean)}.
     *
     * @param documentReference the reference to the document to clean from spam
     * @param authorReferences the references to the authors for which to remove all changes from the document
     * @param skipActivityStream if true then don't generate events in the Activity Stream for the changes made to
     * @throws AntiSpamException if an error occurs
     */
    @Programming
    public void cleanDocument(DocumentReference documentReference, Collection<DocumentReference> authorReferences,
        boolean skipActivityStream) throws AntiSpamException
    {
        checkForProgrammingRights();
        this.cleaner.cleanDocument(documentReference, authorReferences, skipActivityStream);
    }

    @Programming
    public List<DocumentReference> getDocumentsForAuthor(DocumentReference authorReference, int nb, int offset)
        throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.cleaner.getDocumentsForAuthor(authorReference, nb, offset);
    }

    /**
     * See {@link SpamChecker#isSpam(java.io.Reader, Map)}.
     *
     * @param checkerHint the hint to use to find the spam checker to use
     * @param content the content to check for spam
     * @param parameters the parameters to pass to the spam checker
     * @return {@code true} if the passed content is considered spam, {@code false} otherwise
     * @throws AntiSpamException if an error occurs
     */
    public boolean isSpam(String checkerHint, String content, Map<String, Object> parameters) throws AntiSpamException
    {
        return getSpamChecker(checkerHint).isSpam(new StringReader(content), parameters);
    }

    /**
     * See {@link SpamChecker#isSpam(Reader, Map)}.
     *
     * @param checkerHint the hint to use to find the spam checker to use
     * @param document the document to check for spam
     * @param parameters the parameters to pass to the spam checker
     * @return {@code true} if the passed document is considered spam, {@code false} otherwise
     * @throws AntiSpamException if an error occurs
     */
    public boolean isSpam(String checkerHint, Document document, Map<String, Object> parameters)
        throws AntiSpamException
    {
        try {
            return isSpam(checkerHint, document.getXMLContent(), parameters);
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Error getting XML content for [%s]",
                document.getDocumentReference()), e);
        }
    }

    /**
     *
     * @since 1.8
     */
    @Programming
    public List<DocumentReference> getInactiveAuthors(int elapsedDays, boolean cleanAuthorsWithAvatars, int count)
        throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.cleaner.getInactiveAuthors(elapsedDays, cleanAuthorsWithAvatars, count);
    }

    /**
     * @since 1.8
     */
    @Programming
    public Job cleanAuthors(List<DocumentReference> authorReferences, boolean skipEventStreamRecording)
        throws AntiSpamException
    {
        checkForProgrammingRights();
        DeleteAuthorRequest request = new DeleteAuthorRequest();
        request.setId(DeleteAuthorsJob.TYPE);
        request.setAuthorReferences(authorReferences);
        request.setSkipEventStream(skipEventStreamRecording);
        request.setVerbose(true);

        try {
            return this.jobExecutor.execute(DeleteAuthorsJob.TYPE, request);
        } catch (Exception e) {
            throw new AntiSpamException("Failed to execute the clean authors job", e);
        }
    }

    /**
     * @since 1.8
     */
    public JobStatus getCurrentCleanAuthorJobStatus()
    {
        Job job = this.jobExecutor.getJob(Arrays.asList(DeleteAuthorsJob.TYPE));
        return job == null ? null : job.getStatus();
    }

    /**
     * @since 1.8
     */
    public List<DocumentReference> getKnownUserReferences() throws AntiSpamException
    {
        return new ArrayList<>(this.cleaner.getKnownUserReferences());
    }

    private SpamChecker getSpamChecker(String hint) throws AntiSpamException
    {
        try {
            return this.componentManagerProvider.get().getInstance(SpamChecker.class, hint);
        } catch (ComponentLookupException e) {
            throw new AntiSpamException(String.format("Spam checker for hint [%s] is not available in the system.",
                hint), e);
        }
    }

    /**
     * Search for events in the Event store.
     *
     * @param query the query to use to search for events
     * @return the list of matching events
     * @throws AntiSpamException if the search fails
     * @since 1.9
     */
    @Programming
    public List<Event> searchEvents(EventQuery query) throws AntiSpamException
    {
        checkForProgrammingRights();
        List<Event> events = new ArrayList<>();
        try {
            EventSearchResult result = this.eventStore.search(query);
            result.stream().forEach(events::add);
        } catch (EventStreamException e) {
            String message = String.format("Failed to search for events using query [%s]", query);
            throw new AntiSpamException(message, e);
        }
        return events;
    }

    /**
     * Delete an event from the Event store.
     *
     * @param eventId the id of the event to delete
     * @return a future to the deleted event
     * @throws AntiSpamException if the deletion fails
     * @since 1.9
     */
    @Programming
    public CompletableFuture<Optional<Event>> deleteEvent(String eventId) throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.eventStore.deleteEvent(eventId);
    }

    /**
     * Delete an event from the Event store.
     *
     * @param event the event to delete
     * @return a future to the deleted event
     * @throws AntiSpamException if the deletion fails
     * @since 1.9
     */
    @Programming
    public CompletableFuture<Optional<Event>> deleteEvent(Event event) throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.eventStore.deleteEvent(event);
    }

    /**
     * @return an empty simple event query
     * @since 1.9
     */
    public EventQuery createEventQuery()
    {
        return new SimpleEventQuery();
    }

    /**
     * @param authorReference the reference to the author to check
     * @param documentReference the reference to the document on which to check if the user has Admin rights
     * @return {@code true} if the passed user is a protected user, {@code false} otherwise
     * @since 1.9
     */
    public boolean isProtectedUser(DocumentReference authorReference, DocumentReference documentReference)
    {
        return this.protectionManager.isProtectedUser(authorReference, documentReference);
    }

    private void checkForProgrammingRights() throws AntiSpamException
    {
        if (!this.authorizationManager.hasAccess(Right.PROGRAM)) {
            throw new AntiSpamException("You need Programming Rights to access this api");
        }
    }
}
