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

import java.io.StringReader;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import org.apache.commons.lang3.tuple.Pair;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.contrib.antispam.SpamChecker;
import org.xwiki.contrib.antispam.SpamCleaner;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.api.Document;

@Component
@Named("antispam")
public class AntiSpamScriptService implements ScriptService
{
    @Inject
    private SpamCleaner cleaner;

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private ContextualAuthorizationManager authorizationManager;

    public Pair<List<DocumentReference>, Set<DocumentReference>> getMatchingDocuments(String solrQueryString, int nb,
        int offset) throws AntiSpamException
    {
        return this.cleaner.getMatchingDocuments(solrQueryString, nb, offset);
    }

    public void cleanDocument(DocumentReference documentReference, Collection<DocumentReference> authorReferences,
        boolean skipActivityStream) throws AntiSpamException
    {
        if (this.authorizationManager.hasAccess(Right.PROGRAM)) {
            this.cleaner.cleanDocument(documentReference, authorReferences, skipActivityStream);
        } else {
            throw new AntiSpamException("You need Programming Rights to access this api");
        }
    }

    public List<DocumentReference> getDocumentsForAuthor(DocumentReference authorReference, int nb, int offset)
        throws AntiSpamException
    {
        return this.cleaner.getDocumentsForAuthor(authorReference, nb, offset);
    }

    public boolean isSpam(String checkerHint, String content, Map<String, Object> parameters) throws AntiSpamException
    {
        return getSpamChecker(checkerHint).isSpam(new StringReader(content), parameters);
    }

    public boolean isSpam(String checkerHint, Document document, Map<String, Object> parameters)
        throws AntiSpamException
    {
        try {
            return isSpam(checkerHint, document.getXMLContent(), parameters);
        } catch (Exception e) {
            throw new AntiSpamException(String.format("Error getting XML content for [%s]",
                document.getDocumentReference()), e);
        }
    }

    private SpamChecker getSpamChecker(String hint) throws AntiSpamException
    {
        try {
            return this.componentManagerProvider.get().getInstance(SpamChecker.class, hint);
        } catch (ComponentLookupException e) {
            throw new AntiSpamException(String.format("Spam checker for hint [%s] is not available in the system.",
                hint), e);
        }
    }
}
