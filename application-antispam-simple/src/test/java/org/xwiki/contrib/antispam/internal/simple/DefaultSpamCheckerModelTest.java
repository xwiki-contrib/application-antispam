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

import javax.inject.Provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.model.document.DocumentAuthors;
import org.xwiki.model.internal.document.DefaultDocumentAuthors;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.SuperAdminUserReference;
import org.xwiki.user.UserReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultSpamCheckerModel}.
 *
 * @version $Id$
 */
@ComponentTest
class DefaultSpamCheckerModelTest
{
    @InjectMockComponents
    private DefaultSpamCheckerModel model;

    @MockComponent
    private Provider<XWikiContext> contextProvider;

    private XWikiContext xcontext;

    private XWiki xwiki;

    @BeforeEach
    void setUp()
    {
        this.xcontext = mock(XWikiContext.class);
        this.xwiki = mock(XWiki.class);
        when(this.contextProvider.get()).thenReturn(this.xcontext);
        when(this.xcontext.getWiki()).thenReturn(this.xwiki);
    }

    @Test
    void disableUserKeepsTheAuthorsUsedForRights() throws Exception
    {
        DocumentReference userReference = new DocumentReference("xwiki", "XWiki", "User");
        UserReference userUserReference = mock(UserReference.class);
        UserReference contentAuthorReference = mock(UserReference.class);

        XWikiDocument userDocument = mock(XWikiDocument.class);
        DocumentAuthors authors = new DefaultDocumentAuthors(userDocument);
        authors.setEffectiveMetadataAuthor(userUserReference);
        authors.setOriginalMetadataAuthor(userUserReference);
        authors.setContentAuthor(contentAuthorReference);
        when(userDocument.getAuthors()).thenReturn(authors);
        BaseObject userObject = mock(BaseObject.class);
        when(userDocument.getXObject(any(EntityReference.class))).thenReturn(userObject);
        when(this.xwiki.getDocument((EntityReference) userReference, this.xcontext)).thenReturn(userDocument);

        this.model.disableUser(userReference);

        verify(userObject).set("active", 0, this.xcontext);
        verify(this.xwiki).saveDocument(userDocument, "Disabling user considered as spammer", true, this.xcontext);
        assertEquals(userUserReference, authors.getEffectiveMetadataAuthor());
        assertEquals(contentAuthorReference, authors.getContentAuthor());
        assertEquals(SuperAdminUserReference.INSTANCE, authors.getOriginalMetadataAuthor());
    }
}
