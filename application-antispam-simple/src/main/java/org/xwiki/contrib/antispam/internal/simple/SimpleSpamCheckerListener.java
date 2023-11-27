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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.bridge.event.DocumentCreatingEvent;
import org.xwiki.bridge.event.DocumentUpdatingEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.container.Container;
import org.xwiki.container.Request;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.contrib.antispam.SpamCheckerProtectionManager;
import org.xwiki.contrib.antispam.SpamChecker;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
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

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private SpamCheckerProtectionManager protectionManager;

    @Override
    public String getName()
    {
        return "SimpleSpamChecker";
    }

    @Override
    public List<Event> getEvents()
    {
        return Arrays.asList(new DocumentUpdatingEvent(), new DocumentCreatingEvent());
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        if (!(source instanceof XWikiDocument) || !(data instanceof XWikiContext)) {
            return;
        }

        // If we're already handling a document then don't check any other triggered indirectly since it's not required,
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

        // Don't check for spam when editing a page located in the AntiSpam space & in any excluded spaces
        if (document.getDocumentReference().getLastSpaceReference().getName().equals("AntiSpam")
            || this.model.getExcludedSpaces().contains(this.entityReferenceSerializer.serialize(
            document.getDocumentReference().getParent())))
        {
            return;
        }

        Map<String, Object> parameters = new HashMap<>();

        // Add the IP to the parameters so that content created by known spammer IP can always be considered as spam
        String ip = extractIP();
        if (ip != null) {
            parameters.put("ip", ip);
        }

        // Add the document and author references to the parameters so that the spam checker can log matching keywords
        // when spam is found.
        parameters.put("authorReference", xcontext.getUserReference());
        parameters.put("documentReference", document.getDocumentReference());

        try {
            // Note: we serialize the document to XML to have its full content including xobjects, xclass definition,
            // title, name, etc.
            boolean isSpam =
                this.checker.isSpam(new StringReader(document.toXML(true, false, false, false, xcontext)), parameters);
            if (isSpam) {
                // Mark that we're handling some spam so that when we save documents in the process they're not
                // processed as spam which could lead to infinite recursions.
                xcontext.put(XCONTEXT_MARKER_KEY, true);

                // Disable the user
                DocumentReference currentUserReference = xcontext.getUserReference();
                disableUser(currentUserReference, ip, document.getDocumentReference());

                // Cancel the event
                String message = String.format("The content of [%s] is considered to be spam and save has been "
                    + "cancelled", document.getDocumentReference());
                if (event instanceof CancelableEvent) {
                    ((CancelableEvent) event).cancel(message);
                } else {
                    // We're on a version of XWiki that doesn't support cancelling Document saving events. Thus, we
                    // throw an Error (and not an Exception since that one would be caught by the Observation Manager)
                    // to stop the save!
                    throw new Error(message);
                }
            }
        } catch (Exception e) {
            // We failed to check if the content is spam or not, let is go through but log an error
            logger.error("Failed to check for spam in content of [{}]. Please verify if the content contains spam "
                + "manually ", document.getDocumentReference(), e);
        }
    }

    /**
     * Disable the user (so that it cannot log again) but also log it and logs its ip. Don't disable any protected user
     * (known user, known group, admin rights user).
     *
     * @param userReference the reference to the user to disable
     * @param ip the user IP address
     * @param documentReference the reference to the document containing spam
     * @throws AntiSpamException if there's an error disabling the user
     */
    private void disableUser(DocumentReference userReference, String ip, DocumentReference documentReference)
        throws AntiSpamException
    {
        if (!this.protectionManager.isProtectedUser(userReference, documentReference)) {
            // Disable the user
            this.model.disableUser(userReference);

            // Add the user to a list of disabled users because they tried adding some spam
            this.model.logDisabledUser(userReference);

            // Add the IP to the list of spammers
            if (ip != null) {
                this.model.logSpamAddress(ip);
            }
        } else {
            this.logger.warn("User [{}] tried to save document [{}] which contains spam. Since that user is protected,"
                + " it has not been disabled.", userReference, documentReference);
        }
    }

    private String extractIP()
    {
        String ip = null;
        Request request = this.container.getRequest();
        if (request instanceof ServletRequest) {
            // First check if there's a XFF header
            // See https://en.wikipedia.org/wiki/X-Forwarded-For
            HttpServletRequest servletRequest = ((ServletRequest) request).getHttpServletRequest();
            String xffHeaderValue = servletRequest.getHeader("X-Forwarded-For");
            if (!StringUtils.isBlank(xffHeaderValue)) {
                // The header value is a list, and we need to take the right IP. Deciding which one to take depends on
                // the setup. If XWiki is behind a proxy then the right IP to use is the last but one, otherwise, it's
                // the last one (if XWiki is behind 2 proxies then it's the one before the last but one, etc.).
                // Since this cannot be guessed, we've left it to the user of this extension to configure.
                int position = this.model.getXFFHeaderIPPosition();
                String[] ips = StringUtils.split(xffHeaderValue, ", ");
                if (position >= 0 && (ips.length - 1 - position >= 0)) {
                    ip = ips[ips.length - 1 - position];
                } else {
                    // No position defined or invalid position, default to the first one!
                    ip = ips[0];
                }
            }
            if (ip == null) {
                ip = servletRequest.getRemoteAddr();
            }
        }
        return ip;
    }
}
