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

    @Programming
    public List<MatchingReference> getMatchingDocuments(String solrQueryString, int nb, int offset)
        throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.cleaner.getMatchingDocuments(solrQueryString, nb, offset);
    }

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

    public boolean isSpam(String checkerHint, String content, Map<String, Object> parameters) throws AntiSpamException
    {
        return getSpamChecker(checkerHint).isSpam(new StringReader(content), parameters);
    }

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
    public Set<String> getKnownUserReferences() throws AntiSpamException
    {
        Set<String> userReferencesAsString = new HashSet<>();
        for (DocumentReference userReference : this.cleaner.getKnownUserReferences()) {
            userReferencesAsString.add(this.entityReferenceSerializer.serialize(userReference));
        }
        return userReferencesAsString;
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

    @Programming
    public List<Event> searchEvents(EventQuery query) throws AntiSpamException
    {
        checkForProgrammingRights();
        List<Event> events = new ArrayList<>();
        try {
            EventSearchResult result = this.eventStore.search(query);
            result.stream().forEach(event -> {
                events.add(event);
            });
        } catch (EventStreamException e) {
            String message = String.format("Failed to search for events using query [%s]", query);
            throw new AntiSpamException(message, e);
        }
        return events;
    }

    @Programming
    public CompletableFuture<Optional<Event>> deleteEvent(String eventId) throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.eventStore.deleteEvent(eventId);
    }

    @Programming
    public CompletableFuture<Optional<Event>> deleteEvent(Event event) throws AntiSpamException
    {
        checkForProgrammingRights();
        return this.eventStore.deleteEvent(event);
    }

    public EventQuery createEventQuery()
    {
        return new SimpleEventQuery();
    }

    private void checkForProgrammingRights() throws AntiSpamException
    {
        if (!this.authorizationManager.hasAccess(Right.PROGRAM)) {
            throw new AntiSpamException("You need Programming Rights to access this api");
        }
    }
}
