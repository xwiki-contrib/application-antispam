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
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.antispam.SpamCheckerResult;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SimpleSpamChecker}.
 *
 * @version $Id$
 */
@ComponentTest
class SimpleSpamCheckerTest
{
    /**
     * Content on which the {@code a.*z} keyword regex takes a time quadratic in the content length to evaluate.
     */
    private static final String SLOW_CONTENT = StringUtils.repeat('a', 200000);

    @RegisterExtension
    private LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.WARN);

    @InjectMockComponents
    private SimpleSpamChecker spamChecker;

    @MockComponent
    private SpamCheckerModel model;

    @Test
    void isSpam() throws Exception
    {
        // Note: we test the ability to use regex symbols in the spam keywords.
        String content = "test spam1 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx spammer2";
        when(this.model.getSpamKeywords()).thenReturn(Arrays.asList("spam1", "spam...2", "spam3"));

        Map<String, Object> parameters = new HashMap<>();
        DocumentReference authorReference = new DocumentReference("wiki", "XWiki", "Author1");
        parameters.put("authorReference", authorReference);
        DocumentReference documentReference = new DocumentReference("wiki", "Space", "Page");
        parameters.put("documentReference", documentReference);

        SpamCheckerResult result = this.spamChecker.isSpam(new StringReader(content), parameters);

        assertTrue(result.isSpam());
        assertEquals(2, result.getMatchedContent().size());
        assertEquals("test spam1 xxxxxxxxxxxxxxxxxxxxxxxxxxxxx", result.getMatchedContent().get("spam1"));
        assertEquals("xxxxxxxxxxxxxxxxxxxxxxxxxxxxx spammer2", result.getMatchedContent().get("spammer2"));

        verify(this.model).logMatchingSpamKeywords(result.getMatchedContent(), authorReference, documentReference);
    }

    @Test
    void isSpamWhenMatchingTakesTooLong() throws Exception
    {
        FieldUtils.writeField(this.spamChecker, "matchTimeout", 100L, true);
        when(this.model.getSpamKeywords()).thenReturn(Arrays.asList("spam1", "a.*z"));

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("documentReference", new DocumentReference("wiki", "Space", "Page"));

        SpamCheckerResult result = assertTimeoutPreemptively(Duration.ofSeconds(10),
            () -> this.spamChecker.isSpam(new StringReader(SLOW_CONTENT), parameters));

        assertFalse(result.isSpam());
        assertEquals(1, this.logCapture.size());
        assertEquals("Stopped looking for spam keywords in the content of [wiki:Space.Page] after [100] ms. Only the "
            + "keywords found before that have been considered. Please verify if the content contains spam manually.",
            this.logCapture.getMessage(0));
    }

    @Test
    void isSpamWhenMatchingTakesTooLongAfterAMatch() throws Exception
    {
        FieldUtils.writeField(this.spamChecker, "matchTimeout", 100L, true);
        when(this.model.getSpamKeywords()).thenReturn(Arrays.asList("spam1", "a.*z"));

        Map<String, Object> parameters = new HashMap<>();
        DocumentReference authorReference = new DocumentReference("wiki", "XWiki", "Author1");
        parameters.put("authorReference", authorReference);
        DocumentReference documentReference = new DocumentReference("wiki", "Space", "Page");
        parameters.put("documentReference", documentReference);

        SpamCheckerResult result = assertTimeoutPreemptively(Duration.ofSeconds(10),
            () -> this.spamChecker.isSpam(new StringReader("spam1 " + SLOW_CONTENT), parameters));

        assertTrue(result.isSpam());
        assertEquals(1, result.getMatchedContent().size());
        assertEquals("spam1 " + StringUtils.repeat('a', 29), result.getMatchedContent().get("spam1"));
        verify(this.model).logMatchingSpamKeywords(result.getMatchedContent(), authorReference, documentReference);
        assertEquals(1, this.logCapture.size());
        assertTrue(this.logCapture.getMessage(0).startsWith("Stopped looking for spam keywords"));
    }
}
