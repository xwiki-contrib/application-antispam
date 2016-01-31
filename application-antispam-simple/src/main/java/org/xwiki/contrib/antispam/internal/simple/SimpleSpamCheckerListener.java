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

        XWikiDocument document = (XWikiDocument) source;

        // Don't check for spam when editing the Keyworsd and IP address documents as they contain spam keywords and IP!
        if (this.model.isSpamAddressDocument(document.getDocumentReference())
            || this.model.isSpamKeywordDocument(document.getDocumentReference()))
        {
            return;
        }

        Map<String, Object> parameters = Collections.emptyMap();
        Request request = this.container.getRequest();
        if (request instanceof ServletRequest) {
            String ip =  ((ServletRequest) request).getHttpServletRequest().getRemoteAddr();
            parameters = Collections.singletonMap("ip", (Object) ip);
        }

        try {
            // TODO: Also check xobjects. Use case #1: spam in comments
            boolean isSpam = this.checker.isSpam(new StringReader(document.getContent()), parameters);
            if (isSpam) {
                // Cancel the event
                if (event instanceof CancelableEvent) {
                    ((CancelableEvent) event).cancel(String.format("The content of [%s] is considered to be spam",
                        document.getDocumentReference()));
                    // TODO:
                    // - Add the IP address to the list of known spammer ip addresses
                    // - Disable the user and add its reference to the list of spam users
                    //XWikiContext xcontext = (XWikiContext) data;
                }
            }
        } catch (AntiSpamException e) {
            // We failed to check if the content is spam or not, let is go through but log an error
            logger.error("Failed to check for spam in content of [{}]", document.getDocumentReference(), e);
        }
    }
}
