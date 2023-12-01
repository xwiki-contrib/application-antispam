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
import java.util.Collections;
import java.util.Map;

import javax.inject.Named;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.bridge.event.DocumentUpdatingEvent;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
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
}
