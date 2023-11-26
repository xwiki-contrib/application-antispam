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
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

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
    @InjectMockComponents
    private SimpleSpamChecker spamChecker;

    @MockComponent
    private SpamCheckerModel model;

    @Test
    void isSpam() throws Exception
    {
        // Note: we test the ability to use regex symbols in the spam keywords.
        String content = "test spam1 content spammer2";
        when(this.model.getSpamKeywords()).thenReturn(Arrays.asList("spam1", "spam...2", "spam3"));

        Map<String, Object> parameters = new HashMap<>();
        DocumentReference authorReference = new DocumentReference("wiki", "XWiki", "Author1");
        parameters.put("authorReference", authorReference);
        DocumentReference documentReference = new DocumentReference("wiki", "Space", "Page");
        parameters.put("documentReference", documentReference);

        boolean isSpam = this.spamChecker.isSpam(new StringReader(content), parameters);
        assertTrue(isSpam);

        verify(this.model).logMatchingSpamKeywords(Arrays.asList("spam1", "spammer2"), authorReference,
            documentReference);
    }
}
