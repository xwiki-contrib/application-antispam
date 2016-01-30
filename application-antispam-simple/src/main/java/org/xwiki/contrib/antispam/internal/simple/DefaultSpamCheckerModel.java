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
import java.util.List;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.io.IOUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.EntityReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;

@Component
@Singleton
public class DefaultSpamCheckerModel implements SpamCheckerModel
{
    private static final EntityReference ADDRESSES_DOCUMENT_REFERENCE = new EntityReference("IPAddresses",
        EntityType.DOCUMENT, new EntityReference("AntiSpam", EntityType.SPACE));

    private static final EntityReference KEYWORDS_DOCUMENT_REFERENCE = new EntityReference("Keywords",
        EntityType.DOCUMENT, new EntityReference("AntiSpam", EntityType.SPACE));

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Override
    public List<String> getSpamAddresses() throws AntiSpamException
    {
        List<String> addresses;
        try {
            XWikiDocument addressDocument = getDocument(ADDRESSES_DOCUMENT_REFERENCE);
            // Parse the IPs from the content
            addresses = IOUtils.readLines(new StringReader(addressDocument.getContent()));
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to get document containing spam IP addresses [%s]",
                ADDRESSES_DOCUMENT_REFERENCE.toString()), e);
        }
        return addresses;
    }

    @Override
    public List<String> getSpamKeywords() throws AntiSpamException
    {
        List<String> keywords;
        try {
            XWikiDocument keywordsDocument = getDocument(KEYWORDS_DOCUMENT_REFERENCE);
            // Parse the Keywords from the content
            keywords = IOUtils.readLines(new StringReader(keywordsDocument.getContent()));
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to get document containing spam keywords [%s]",
                KEYWORDS_DOCUMENT_REFERENCE.toString()), e);
        }
        return keywords;
    }

    private XWikiDocument getDocument(EntityReference reference) throws Exception
    {
        XWikiContext xcontext = this.contextProvider.get();
        XWiki xwiki = xcontext.getWiki();
        return xwiki.getDocument(reference, xcontext);
    }
}
