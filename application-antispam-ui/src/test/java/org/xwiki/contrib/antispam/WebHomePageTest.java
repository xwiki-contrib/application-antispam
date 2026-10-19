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
package org.xwiki.contrib.antispam;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.antispam.script.AntiSpamScriptService;
import org.xwiki.csrf.script.CSRFTokenScriptService;
import org.xwiki.eventstream.Event;
import org.xwiki.eventstream.query.SimpleEventQuery;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.rendering.configuration.ExtendedRenderingConfiguration;
import org.xwiki.rendering.internal.macro.message.ErrorMessageMacro;
import org.xwiki.rendering.internal.macro.message.InfoMessageMacro;
import org.xwiki.rendering.internal.syntax.SyntaxConverter;
import org.xwiki.rendering.macro.MacroCategoryManager;
import org.xwiki.rendering.script.RenderingScriptService;
import org.xwiki.script.service.ScriptService;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.test.page.HTML50ComponentList;
import org.xwiki.test.page.PageTest;
import org.xwiki.test.page.XWikiSyntax21ComponentList;

import com.xpn.xwiki.doc.XWikiDocument;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Page test for the document {@code AntiSpam.WebHome}.
 *
 * @version $Id$
 */
@ComponentList({
    RenderingScriptService.class,
    SyntaxConverter.class,
    InfoMessageMacro.class,
    ErrorMessageMacro.class
})
@HTML50ComponentList
@XWikiSyntax21ComponentList
class WebHomePageTest extends PageTest
{
    private static final DocumentReference WEB_HOME_REFERENCE = new DocumentReference("xwiki", "AntiSpam", "WebHome");

    private static final String SPECIAL_NAME = "a]]{{info}}x{{/info}}<b>y</b>[[z";

    @MockComponent
    private ExtendedRenderingConfiguration extendedRenderingConfiguration;

    @MockComponent
    private MacroCategoryManager macroCategoryManager;

    private AntiSpamScriptService antiSpamScriptService;

    private CSRFTokenScriptService csrfScriptService;

    @BeforeEach
    void setUp() throws Exception
    {
        this.antiSpamScriptService = mock(AntiSpamScriptService.class);
        this.componentManager.registerComponent(ScriptService.class, "antispam", this.antiSpamScriptService);
        when(this.antiSpamScriptService.createEventQuery()).thenReturn(new SimpleEventQuery());

        this.csrfScriptService = mock(CSRFTokenScriptService.class);
        this.componentManager.registerComponent(ScriptService.class, "csrf", this.csrfScriptService);
        when(this.csrfScriptService.getToken()).thenReturn("token");

        loadPage(WEB_HOME_REFERENCE);
    }

    @Test
    void displayLatestChangesWithSpecialCharactersInReferences() throws Exception
    {
        DocumentReference existingUserReference = createDocument("XWiki", SPECIAL_NAME + " user");
        DocumentReference missingUserReference = new DocumentReference("xwiki", "XWiki", SPECIAL_NAME + " missing");
        DocumentReference existingDocumentReference = createDocument("Sandbox", SPECIAL_NAME + " page");
        DocumentReference missingDocumentReference = new DocumentReference("xwiki", "Sandbox", SPECIAL_NAME + " gone");

        List<Event> events = Arrays.asList(
            mockEvent("1", existingDocumentReference, existingUserReference),
            mockEvent("2", missingDocumentReference, missingUserReference));
        when(this.antiSpamScriptService.searchEvents(any())).thenReturn(events);

        Document html = renderHTMLPage(WEB_HOME_REFERENCE);

        assertNoInterpretedMarkup(html);
        String text = html.select("#events").text();
        assertTrue(text.contains(existingDocumentReference + " (v1.1)"), text);
        assertTrue(text.contains(missingDocumentReference + " (v1.1)"), text);
        assertTrue(text.contains(existingUserReference.toString()), text);
        assertTrue(text.contains(missingUserReference.toString()), text);
        Set<String> linkTexts = html.select("#events a").stream().map(Element::text).collect(Collectors.toSet());
        assertTrue(linkTexts.contains(existingDocumentReference + " (v1.1)"), linkTexts.toString());
        assertTrue(linkTexts.contains(existingUserReference.toString()), linkTexts.toString());
    }

    @Test
    void displaySearchResultsWithSpecialCharactersInReferences() throws Exception
    {
        this.request.put("query", "term");
        this.request.put("form_token", "token");
        when(this.csrfScriptService.isTokenValid("token")).thenReturn(true);

        DocumentReference authorReference = createDocument("XWiki", SPECIAL_NAME + " user");
        DocumentReference documentReference = createDocument("Sandbox", SPECIAL_NAME + " page");
        DocumentReference protectedDocumentReference = createDocument("Sandbox", SPECIAL_NAME + " protected");
        when(this.antiSpamScriptService.getMatchingDocuments("\"term\"", 500, 0)).thenReturn(Arrays.asList(
            new MatchingReference(documentReference, authorReference),
            new MatchingReference(protectedDocumentReference, authorReference)));
        when(this.antiSpamScriptService.getLastAuthorReferences(any()))
            .thenReturn(Collections.singleton(authorReference));
        when(this.antiSpamScriptService.isProtectedUser(authorReference, protectedDocumentReference))
            .thenReturn(true);

        Document html = renderHTMLPage(WEB_HOME_REFERENCE);

        assertNoInterpretedMarkup(html);
        Set<String> linkTexts = html.select("a").stream().map(Element::text).collect(Collectors.toSet());
        assertTrue(linkTexts.contains(documentReference.toString()), linkTexts.toString());
        assertTrue(linkTexts.contains(protectedDocumentReference.toString()), linkTexts.toString());
        assertTrue(linkTexts.contains(authorReference.toString()), linkTexts.toString());
        String errorText = html.select(".box.errormessage").text();
        assertTrue(errorText.contains("This change was made by [" + authorReference + "]"), errorText);
    }

    private void assertNoInterpretedMarkup(Document html)
    {
        assertTrue(html.select(".box.infomessage").isEmpty(), html.html());
        assertTrue(html.select("b").isEmpty(), html.html());
    }

    private DocumentReference createDocument(String space, String name) throws Exception
    {
        DocumentReference reference = new DocumentReference("xwiki", space, name);
        this.xwiki.saveDocument(new XWikiDocument(reference), this.context);
        return reference;
    }

    private Event mockEvent(String id, DocumentReference documentReference, DocumentReference userReference)
    {
        Event event = mock(Event.class);
        when(event.getId()).thenReturn(id);
        when(event.getDocument()).thenReturn(documentReference);
        when(event.getDocumentVersion()).thenReturn("1.1");
        when(event.getUser()).thenReturn(userReference);
        when(event.getDate()).thenReturn(new Date(0));
        when(event.getType()).thenReturn("update");
        return event;
    }
}
