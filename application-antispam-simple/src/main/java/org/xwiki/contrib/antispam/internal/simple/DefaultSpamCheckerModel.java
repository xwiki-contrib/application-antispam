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
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

@Component
@Singleton
public class DefaultSpamCheckerModel implements SpamCheckerModel
{
    private static final EntityReference ADDRESSES_DOCUMENT_REFERENCE = new EntityReference("IPAddresses",
        EntityType.DOCUMENT, new EntityReference("AntiSpam", EntityType.SPACE));

    private static final EntityReference KEYWORDS_DOCUMENT_REFERENCE = new EntityReference("Keywords",
        EntityType.DOCUMENT, new EntityReference("AntiSpam", EntityType.SPACE));

    private static final EntityReference DISABLED_USERS_DOCUMENT_REFERENCE = new EntityReference("DisabledUsers",
        EntityType.DOCUMENT, new EntityReference("AntiSpam", EntityType.SPACE));

    private static final EntityReference CONFIG_DOCUMENT_REFERENCE = new EntityReference("AntiSpamConfig",
        EntityType.DOCUMENT, new EntityReference("AntiSpam", EntityType.SPACE));

    private static final EntityReference USER_XCLASS_REFERENCE = new EntityReference("XWikiUsers",
        EntityType.DOCUMENT, new EntityReference("XWiki", EntityType.SPACE));

    private static final EntityReference CONFIG_XCLASS_REFERENCE = new EntityReference("AntiSpamConfigClass",
        EntityType.DOCUMENT, new EntityReference("AntiSpam", EntityType.SPACE));

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Override
    public List<String> getSpamAddresses() throws AntiSpamException
    {
        List<String> addresses;
        try {
            XWikiContext xcontext = getXWikiContext();
            XWikiDocument addressDocument = getDocument(ADDRESSES_DOCUMENT_REFERENCE, xcontext);
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
            XWikiContext xcontext = getXWikiContext();
            XWikiDocument keywordsDocument = getDocument(KEYWORDS_DOCUMENT_REFERENCE, xcontext);
            // Parse the Keywords from the content
            keywords = IOUtils.readLines(new StringReader(keywordsDocument.getContent()));
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to get document containing spam keywords [%s]",
                KEYWORDS_DOCUMENT_REFERENCE.toString()), e);
        }
        return keywords;
    }

    @Override
    public boolean isSpamAddressDocument(DocumentReference reference)
    {
        return reference.getName().equals(ADDRESSES_DOCUMENT_REFERENCE.getName())
            && reference.getParent().getName().equals(ADDRESSES_DOCUMENT_REFERENCE.getParent().getName());
    }

    @Override
    public boolean isSpamKeywordDocument(DocumentReference reference)
    {
        return reference.getName().equals(KEYWORDS_DOCUMENT_REFERENCE.getName())
            && reference.getParent().getName().equals(KEYWORDS_DOCUMENT_REFERENCE.getParent().getName());
    }

    @Override
    public boolean isDisabledUserDocument(DocumentReference reference)
    {
        return reference.getName().equals(DISABLED_USERS_DOCUMENT_REFERENCE.getName())
            && reference.getParent().getName().equals(DISABLED_USERS_DOCUMENT_REFERENCE.getParent().getName());
    }

    @Override
    public void logSpamAddress(String ip) throws AntiSpamException
    {
        try {
            XWikiContext xcontext = getXWikiContext();
            XWikiDocument addressDocument = getDocument(ADDRESSES_DOCUMENT_REFERENCE, xcontext);
            // Only log the IP if it's not already in the list
            List<String> loggedIPs = IOUtils.readLines(new StringReader(addressDocument.getContent()));
            if (!loggedIPs.contains(ip)) {
                addressDocument.setContent(ip + "\n" + addressDocument.getContent());
                getXWiki(xcontext).saveDocument(addressDocument, "Adding new spammer ip", true, xcontext);
            }
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to add ip [%s]to containing spam IP addresses[%s]",
                ip, KEYWORDS_DOCUMENT_REFERENCE.toString()), e);
        }
    }

    @Override
    public void disableUser(DocumentReference authorReference) throws AntiSpamException
    {
        try {
            XWikiContext xcontext = getXWikiContext();
            XWikiDocument authorDocument = getDocument(authorReference, xcontext);
            BaseObject xwikiUserObject = authorDocument.getXObject(USER_XCLASS_REFERENCE);
            xwikiUserObject.set("active", 0, xcontext);
            getXWiki(xcontext).saveDocument(authorDocument, "Disabling user considered as spammer", true, xcontext);
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to disable user [%s]", authorReference), e);
        }
    }

    @Override
    public void logDisabledUser(DocumentReference authorReference) throws AntiSpamException
    {
        try {
            XWikiContext xcontext = getXWikiContext();
            XWikiDocument disabledUsersDocument = getDocument(DISABLED_USERS_DOCUMENT_REFERENCE, xcontext);
            // Only log the user if he's not already in the list
            List<String> disabledUsers = IOUtils.readLines(new StringReader(disabledUsersDocument.getContent()));
            String authorReferenceAsString = this.entityReferenceSerializer.serialize(authorReference);
            if (!disabledUsers.contains(authorReferenceAsString)) {
                disabledUsersDocument.setContent(authorReferenceAsString + "\n" + disabledUsersDocument.getContent());
                getXWiki(xcontext).saveDocument(disabledUsersDocument, String.format("Adding user [%s]",
                    authorReference), true, xcontext);
            }
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Failed to log disabled spam user [%s] to [%s]",
                authorReference, DISABLED_USERS_DOCUMENT_REFERENCE.toString()), e);
        }
    }

    @Override
    public boolean iSpamCheckingActive()
    {
        boolean isSpamCheckingActive;
        try {
            XWikiContext xcontext = getXWikiContext();
            XWikiDocument configDocument = getDocument(CONFIG_DOCUMENT_REFERENCE, xcontext);
            BaseObject configObject = configDocument.getXObject(CONFIG_XCLASS_REFERENCE);
            if (configObject != null) {
                int active = configObject.getIntValue("active");
                // By default spam checking is true, unless set to false
                isSpamCheckingActive = active == 0 ? false : true;
            } else {
                // No xobject, we consider it's active
                isSpamCheckingActive = true;
            }
        } catch (Exception e) {
            this.logger.error("Failed to access AntiSpam configuration", e);
            isSpamCheckingActive = true;
        }
        return isSpamCheckingActive;
    }

    private XWikiDocument getDocument(EntityReference reference, XWikiContext xcontext) throws Exception
    {
        XWiki xwiki = xcontext.getWiki();
        return xwiki.getDocument(reference, xcontext);
    }

    private XWikiContext getXWikiContext()
    {
        return this.contextProvider.get();
    }

    private XWiki getXWiki(XWikiContext xcontext)
    {
        return xcontext.getWiki();
    }
}
