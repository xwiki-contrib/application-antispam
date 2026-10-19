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

import java.util.Collections;

import org.jsoup.nodes.Document;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.antispam.script.AntiSpamScriptService;
import org.xwiki.csrf.script.CSRFTokenScriptService;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.rendering.configuration.ExtendedRenderingConfiguration;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Page test for the document {@code AntiSpam.CleanInactiveUsers}.
 *
 * @version $Id$
 */
@ComponentList({
    RenderingScriptService.class,
    SyntaxConverter.class,
    InfoMessageMacro.class
})
@HTML50ComponentList
@XWikiSyntax21ComponentList
class CleanInactiveUsersPageTest extends PageTest
{
    private static final DocumentReference CLEAN_INACTIVE_USERS_REFERENCE =
        new DocumentReference("xwiki", "AntiSpam", "CleanInactiveUsers");

    @MockComponent
    private ExtendedRenderingConfiguration extendedRenderingConfiguration;

    @MockComponent
    private MacroCategoryManager macroCategoryManager;

    private AntiSpamScriptService antiSpamScriptService;

    @BeforeEach
    void setUp() throws Exception
    {
        this.antiSpamScriptService = mock(AntiSpamScriptService.class);
        this.componentManager.registerComponent(ScriptService.class, "antispam", this.antiSpamScriptService);

        CSRFTokenScriptService csrfScriptService = mock(CSRFTokenScriptService.class);
        this.componentManager.registerComponent(ScriptService.class, "csrf", csrfScriptService);
        when(csrfScriptService.getToken()).thenReturn("token");

        loadPage(CLEAN_INACTIVE_USERS_REFERENCE);
    }

    @Test
    void displayInactiveUsersWithSpecialCharactersInReferences() throws Exception
    {
        DocumentReference userReference =
            new DocumentReference("xwiki", "XWiki", "a]]{{info}}x{{/info}}<b>y</b>}}}[[z");
        this.xwiki.saveDocument(new XWikiDocument(userReference), this.context);
        when(this.antiSpamScriptService.getInactiveAuthors(30, true, 50))
            .thenReturn(Collections.singletonList(userReference));

        Document html = renderHTMLPage(CLEAN_INACTIVE_USERS_REFERENCE);

        assertTrue(html.select(".box.infomessage").isEmpty(), html.html());
        assertTrue(html.select("b").isEmpty(), html.html());
        assertEquals(userReference.toString(), html.select("li a").text(), html.html());
    }
}
