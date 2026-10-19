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

import java.io.Reader;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.xwiki.bridge.event.DocumentUpdatingEvent;
import org.xwiki.container.Container;
import org.xwiki.container.servlet.ServletRequest;
import org.xwiki.contrib.antispam.SpamCheckerProtectionManager;
import org.xwiki.contrib.antispam.SpamChecker;
import org.xwiki.contrib.antispam.SpamCheckerResult;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SimpleSpamCheckerListener}.
 *
 * @version $Id$
 */
@ComponentTest
class SimpleSpamCheckerListenerTest
{
    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

    @InjectMockComponents
    private SimpleSpamCheckerListener listener;

    @MockComponent
    private SpamCheckerModel model;

    @MockComponent
    @Named("simple")
    private SpamChecker checker;

    @MockComponent
    private SpamCheckerProtectionManager protectionManager;

    @MockComponent
    private Container container;

    @Test
    void onEventWhenSpamAndAdminUser() throws Exception
    {
        DocumentUpdatingEvent event = new DocumentUpdatingEvent();

        XWikiContext xcontext = mock(XWikiContext.class);
        when(xcontext.getUserReference()).thenReturn(new DocumentReference("userwiki", "userspace", "userpage"));

        XWikiDocument document = mock(XWikiDocument.class);
        when(document.getDocumentReference()).thenReturn(new DocumentReference("wiki", "space", "page"));
        when(document.toXML(true, false, false, false, xcontext)).thenReturn("some xml");

        when(this.model.iSpamCheckingActive()).thenReturn(true);
        when(this.model.getExcludedSpaces()).thenReturn(Collections.emptyList());

        when(this.checker.isSpam(any(Reader.class), any(Map.class))).thenReturn(new SpamCheckerResult(true));

        // Simulate a protected user.
        when(this.protectionManager.isProtectedUser(any(DocumentReference.class), any(DocumentReference.class)))
            .thenReturn(true);

        this.listener.onEvent(event, document, xcontext);

        // Verify the log message.
        assertEquals(1, logCapture.size());
        assertEquals("User [userwiki:userspace.userpage] tried to save document [wiki:space.page] which contains spam. "
            + "Since that user is protected, it has not been disabled.", logCapture.getMessage(0));
    }

    @Test
    void onEventWhenDocumentInAntiSpamSpace() throws Exception
    {
        DocumentReference documentReference = new DocumentReference("wiki", "AntiSpam", "Keywords");
        XWikiContext xcontext = setUpSave();

        this.listener.onEvent(new DocumentUpdatingEvent(), createDocument(documentReference, xcontext), xcontext);

        verify(this.checker, never()).isSpam(any(Reader.class), any(Map.class));
    }

    @Test
    void onEventWhenDocumentInNestedSpaceNamedAntiSpam() throws Exception
    {
        DocumentReference documentReference =
            new DocumentReference("wiki", Arrays.asList("Sandbox", "AntiSpam"), "Page");
        XWikiContext xcontext = setUpSave();

        this.listener.onEvent(new DocumentUpdatingEvent(), createDocument(documentReference, xcontext), xcontext);

        verify(this.checker).isSpam(any(Reader.class), any(Map.class));
    }

    @Test
    void onEventWhenDocumentInSpaceNestedUnderAntiSpam() throws Exception
    {
        DocumentReference documentReference =
            new DocumentReference("wiki", Arrays.asList("AntiSpam", "Other"), "Page");
        XWikiContext xcontext = setUpSave();

        this.listener.onEvent(new DocumentUpdatingEvent(), createDocument(documentReference, xcontext), xcontext);

        verify(this.checker).isSpam(any(Reader.class), any(Map.class));
    }

    private XWikiContext setUpSave() throws Exception
    {
        XWikiContext xcontext = mock(XWikiContext.class);
        when(xcontext.getUserReference()).thenReturn(new DocumentReference("userwiki", "userspace", "userpage"));
        when(this.model.iSpamCheckingActive()).thenReturn(true);
        when(this.model.getExcludedSpaces()).thenReturn(Collections.emptyList());
        when(this.checker.isSpam(any(Reader.class), any(Map.class))).thenReturn(new SpamCheckerResult(false));
        return xcontext;
    }

    private XWikiDocument createDocument(DocumentReference documentReference, XWikiContext xcontext) throws Exception
    {
        XWikiDocument document = mock(XWikiDocument.class);
        when(document.getDocumentReference()).thenReturn(documentReference);
        when(document.toXML(true, false, false, false, xcontext)).thenReturn("some xml");
        return document;
    }

    @Test
    void onEventWhenSpamUsesLastXFFHeaderIPByDefault() throws Exception
    {
        Map<String, Object> parameters = saveSpam("192.0.2.1, 198.51.100.2", -1, "203.0.113.3");

        assertEquals("198.51.100.2", parameters.get("ip"));
        verify(this.model).logSpamAddress("198.51.100.2");
    }

    @Test
    void onEventWhenSpamUsesLastXFFHeaderIPWhenConfiguredPositionIsTooLarge() throws Exception
    {
        Map<String, Object> parameters = saveSpam("192.0.2.1, 198.51.100.2", 5, "203.0.113.3");

        assertEquals("198.51.100.2", parameters.get("ip"));
        verify(this.model).logSpamAddress("198.51.100.2");
    }

    @Test
    void onEventWhenSpamUsesConfiguredXFFHeaderIPPosition() throws Exception
    {
        Map<String, Object> parameters = saveSpam("192.0.2.1, 2001:db8::1, 198.51.100.2", 1, "203.0.113.3");

        assertEquals("2001:db8::1", parameters.get("ip"));
        verify(this.model).logSpamAddress("2001:db8::1");
    }

    @Test
    void onEventWhenSpamAndNoXFFHeader() throws Exception
    {
        Map<String, Object> parameters = saveSpam(null, -1, "203.0.113.3");

        assertEquals("203.0.113.3", parameters.get("ip"));
        verify(this.model).logSpamAddress("203.0.113.3");
    }

    @Test
    void onEventWhenSpamAndXFFHeaderValueIsNotAnIP() throws Exception
    {
        Map<String, Object> parameters = saveSpam("198.51.100.2, {{/code}}{{info}}x{{/info}}", -1, "203.0.113.3");

        assertFalse(parameters.containsKey("ip"));
        verify(this.model, never()).logSpamAddress(any());
    }

    @Test
    void onEventWhenSpamAndXFFHeaderValueIsAnIPWithScope() throws Exception
    {
        Map<String, Object> parameters = saveSpam("fe80::1%]]", -1, "203.0.113.3");

        assertFalse(parameters.containsKey("ip"));
        verify(this.model, never()).logSpamAddress(any());
    }

    @Test
    void onEventWhenSpamAndXFFHeaderValueIsAHostName() throws Exception
    {
        Map<String, Object> parameters = saveSpam("example.org", -1, "203.0.113.3");

        assertFalse(parameters.containsKey("ip"));
        verify(this.model, never()).logSpamAddress(any());
    }

    private Map<String, Object> saveSpam(String xffHeaderValue, int xffHeaderIPPosition, String remoteAddress)
        throws Exception
    {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        when(httpServletRequest.getHeader("X-Forwarded-For")).thenReturn(xffHeaderValue);
        when(httpServletRequest.getRemoteAddr()).thenReturn(remoteAddress);
        when(this.container.getRequest()).thenReturn(new ServletRequest(httpServletRequest));
        when(this.model.getXFFHeaderIPPosition()).thenReturn(xffHeaderIPPosition);

        XWikiContext xcontext = setUpSave();
        when(this.checker.isSpam(any(Reader.class), any(Map.class))).thenReturn(new SpamCheckerResult(true));

        DocumentReference documentReference = new DocumentReference("wiki", "space", "page");
        this.listener.onEvent(new DocumentUpdatingEvent(), createDocument(documentReference, xcontext), xcontext);

        ArgumentCaptor<Map<String, Object>> parametersCaptor = ArgumentCaptor.forClass(Map.class);
        verify(this.checker).isSpam(any(Reader.class), parametersCaptor.capture());
        return parametersCaptor.getValue();
    }
}
