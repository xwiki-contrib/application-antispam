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

import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.Test;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.rendering.internal.macro.message.InfoMessageMacro;
import org.xwiki.rendering.syntax.Syntax;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.page.HTML50ComponentList;
import org.xwiki.test.page.PageTest;
import org.xwiki.test.page.XWikiSyntax21ComponentList;

import com.xpn.xwiki.doc.XWikiDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Page test for the document {@code AntiSpam.AntiSpamSheet}.
 *
 * @version $Id$
 */
@ComponentList({
    InfoMessageMacro.class
})
@HTML50ComponentList
@XWikiSyntax21ComponentList
class AntiSpamSheetPageTest extends PageTest
{
    private static final DocumentReference SHEET_REFERENCE =
        new DocumentReference("xwiki", "AntiSpam", "AntiSpamSheet");

    @Test
    void displayContentAsText() throws Exception
    {
        String content = "first line {{/code}}{{info}}x{{/info}}{{code}}\n"
            + "{{/html}}<b>second</b> line ]] [[link]] **bold**";

        XWikiDocument sheetDocument = loadPage(SHEET_REFERENCE);

        XWikiDocument document = new XWikiDocument(new DocumentReference("xwiki", "AntiSpam", "Keywords"));
        document.setSyntax(Syntax.PLAIN_1_0);
        document.setContent(content);
        this.xwiki.saveDocument(document, this.context);
        this.context.setDoc(document);

        Document html = renderHTMLPage(sheetDocument);

        assertTrue(html.select(".box.infomessage").isEmpty(), html.html());
        assertTrue(html.select("b").isEmpty(), html.html());
        Elements preElements = html.select("pre");
        assertEquals(1, preElements.size(), html.html());
        assertEquals(content, preElements.get(0).wholeText());
    }
}
