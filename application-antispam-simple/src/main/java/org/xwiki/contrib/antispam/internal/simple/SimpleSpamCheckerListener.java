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

import java.io.StringReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.bridge.event.DocumentCreatingEvent;
import org.xwiki.bridge.event.DocumentUpdatingEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.contrib.antispam.SpamChecker;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.EventListener;
import org.xwiki.observation.event.CancelableEvent;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;

@Component
@Named("SimpleSpamChecker")
@Singleton
public class SimpleSpamCheckerListener implements EventListener
{
    private static final String XCONTEXT_MARKER_KEY = "simpleSpamCheckerListener";

    @Inject
    private Logger logger;

    @Inject
    @Named("simple")
    private SpamChecker checker;

    @Inject
    private SpamCheckerModel model;

    @Inject
    private Container container;

    @Override
    public String getName()
    {
        return "SimpleSpamChecker";
    }

    @Override
    public List<Event> getEvents()
    {
        return Arrays.<Event>asList(new DocumentUpdatingEvent(), new DocumentCreatingEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        if (!(source instanceof XWikiDocument) || !(data instanceof XWikiContext)) {
            return;
        }

        // If we're already handling a document then don't check any other triggered indirectly since it's not required
        // and it would generate infinite loops...
        XWikiContext xcontext = (XWikiContext) data;
        if (xcontext.containsKey(XCONTEXT_MARKER_KEY)) {
            return;
        }

        // Check that spam checking is active and if not, then return
        if (!this.model.iSpamCheckingActive()) {
            return;
        }

        XWikiDocument document = (XWikiDocument) source;

        // Don't check for spam when editing a page located in the AntiSpam space
        if (document.getDocumentReference().getLastSpaceReference().getName().equals("AntiSpam")) {
            return;
        }

        Map<String, Object> parameters = Collections.emptyMap();
        String ip = null;
        Request request = this.container.getRequest();
        if (request instanceof ServletRequest) {
            ip =  ((ServletRequest) request).getHttpServletRequest().getRemoteAddr();
            parameters = Collections.singletonMap("ip", (Object) ip);
        }

        try {
            // TODO: Also check xobjects. Use case #1: spam in comments
            boolean isSpam = this.checker.isSpam(new StringReader(document.getContent()), parameters);
            if (isSpam) {
                // Mark that we're handling some spam so that when we save documents in the process they're not
                // processed as spam which could lead to infinite recursions.
                xcontext.put(XCONTEXT_MARKER_KEY, true);

                // Cancel the event
                if (event instanceof CancelableEvent) {
                    ((CancelableEvent) event).cancel(String.format("The content of [%s] is considered to be spam",
                        document.getDocumentReference()));
                }

                // Disable the user
                DocumentReference currentUserReference = xcontext.getUserReference();
                this.model.disableUser(currentUserReference);

                // Add the user to a list of disabled users because they tried adding some spam
                this.model.logDisabledUser(currentUserReference);

                // Add the IP to the list of spammers
                if (ip != null) {
                    this.model.logSpamAddress(ip);
                }
            }
        } catch (AntiSpamException e) {
            // We failed to check if the content is spam or not, let is go through but log an error
            logger.error("Failed to check for spam in content of [{}]", document.getDocumentReference(), e);
        }
    }
}
