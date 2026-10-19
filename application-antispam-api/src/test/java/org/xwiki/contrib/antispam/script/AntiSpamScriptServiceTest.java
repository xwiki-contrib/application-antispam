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
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.contrib.antispam.SpamChecker;
import org.xwiki.contrib.antispam.SpamCheckerProtectionManager;
import org.xwiki.contrib.antispam.SpamCheckerResult;
import org.xwiki.contrib.antispam.SpamCleaner;
import org.xwiki.job.Job;
import org.xwiki.job.JobExecutor;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.test.annotation.BeforeComponent;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectComponentManager;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.test.mockito.MockitoComponentManager;

import com.xpn.xwiki.api.Document;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AntiSpamScriptService}.
 *
 * @version $Id$
 */
@ComponentTest
class AntiSpamScriptServiceTest
{
    private static final DocumentReference USER_REFERENCE = new DocumentReference("xwiki", "XWiki", "User");

    private static final DocumentReference DOCUMENT_REFERENCE = new DocumentReference("xwiki", "Space", "Page");

    @InjectMockComponents
    private AntiSpamScriptService scriptService;

    @InjectComponentManager
    private MockitoComponentManager componentManager;

    @MockComponent
    private ContextualAuthorizationManager authorizationManager;

    @MockComponent
    private SpamCleaner cleaner;

    @MockComponent
    private JobExecutor jobExecutor;

    @MockComponent
    private SpamCheckerProtectionManager protectionManager;

    private SpamChecker spamChecker;

    @BeforeComponent
    void beforeComponent() throws Exception
    {
        this.componentManager.registerComponent(ComponentManager.class, "context", this.componentManager);
        this.spamChecker = this.componentManager.registerMockComponent(SpamChecker.class, "simple");
    }

    @Test
    void isSpamWithContent() throws Exception
    {
        when(this.authorizationManager.hasAccess(Right.PROGRAM)).thenReturn(true);
        SpamCheckerResult result = mock(SpamCheckerResult.class);
        when(this.spamChecker.isSpam(any(Reader.class), any())).thenReturn(result);

        assertSame(result, this.scriptService.isSpam("simple", "content", Collections.emptyMap()));
    }

    @Test
    void isSpamWithContentWhenNoProgrammingRights()
    {
        Map<String, Object> parameters = Collections.emptyMap();

        AntiSpamException exception =
            assertThrows(AntiSpamException.class, () -> this.scriptService.isSpam("simple", "content", parameters));

        assertEquals("You need Programming Rights to access this api", exception.getMessage());
        verifyNoInteractions(this.spamChecker);
    }

    @Test
    void isSpamWithDocumentWhenNoProgrammingRights()
    {
        Document document = mock(Document.class);
        Map<String, Object> parameters = Collections.emptyMap();

        AntiSpamException exception =
            assertThrows(AntiSpamException.class, () -> this.scriptService.isSpam("simple", document, parameters));

        assertEquals("You need Programming Rights to access this api", exception.getMessage());
        verifyNoInteractions(this.spamChecker);
        verifyNoInteractions(document);
    }

    @Test
    void getCurrentCleanAuthorJobStatus()
    {
        when(this.authorizationManager.hasAccess(Right.PROGRAM)).thenReturn(true);
        Job job = mock(Job.class);
        JobStatus jobStatus = mock(JobStatus.class);
        when(job.getStatus()).thenReturn(jobStatus);
        when(this.jobExecutor.getJob(anyList())).thenReturn(job);

        assertSame(jobStatus, this.scriptService.getCurrentCleanAuthorJobStatus());
    }

    @Test
    void getCurrentCleanAuthorJobStatusWhenNoProgrammingRights()
    {
        assertNull(this.scriptService.getCurrentCleanAuthorJobStatus());
        verifyNoInteractions(this.jobExecutor);
    }

    @Test
    void getKnownUserReferences() throws Exception
    {
        when(this.authorizationManager.hasAccess(Right.PROGRAM)).thenReturn(true);
        when(this.cleaner.getKnownUserReferences()).thenReturn(Collections.singleton(USER_REFERENCE));

        assertEquals(List.of(USER_REFERENCE), this.scriptService.getKnownUserReferences());
    }

    @Test
    void getKnownUserReferencesWhenNoProgrammingRights()
    {
        AntiSpamException exception =
            assertThrows(AntiSpamException.class, () -> this.scriptService.getKnownUserReferences());

        assertEquals("You need Programming Rights to access this api", exception.getMessage());
        verifyNoInteractions(this.cleaner);
    }

    @Test
    void isProtectedUser()
    {
        when(this.authorizationManager.hasAccess(Right.PROGRAM)).thenReturn(true);
        when(this.protectionManager.isProtectedUser(USER_REFERENCE, DOCUMENT_REFERENCE)).thenReturn(true);

        assertTrue(this.scriptService.isProtectedUser(USER_REFERENCE, DOCUMENT_REFERENCE));
    }

    @Test
    void isProtectedUserWhenNoProgrammingRights()
    {
        assertFalse(this.scriptService.isProtectedUser(USER_REFERENCE, DOCUMENT_REFERENCE));
        verifyNoInteractions(this.protectionManager);
    }
}
