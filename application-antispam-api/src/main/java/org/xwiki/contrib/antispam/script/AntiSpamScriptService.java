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

import java.util.Collection;
import java.util.List;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang3.tuple.Pair;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.antispam.AntiSpam;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

@Component
@Named("antispam")
public class AntiSpamScriptService implements ScriptService, AntiSpam
{
    @Inject
    private AntiSpam antiSpam;

    @Inject
    private ContextualAuthorizationManager authorizationManager;

    @Override
    public Pair<List<DocumentReference>, Set<DocumentReference>> getMatchingDocuments(String solrQueryString, int nb,
        int offset) throws AntiSpamException
    {
        return this.antiSpam.getMatchingDocuments(solrQueryString, nb, offset);
    }

    @Override
    public void cleanDocument(DocumentReference documentReference, Collection<DocumentReference> authorReferences,
        boolean skipActivityStream) throws AntiSpamException
    {
        if (this.authorizationManager.hasAccess(Right.PROGRAM)) {
            this.antiSpam.cleanDocument(documentReference, authorReferences, skipActivityStream);
        } else {
            throw new AntiSpamException("You need Programming Rights to access this api");
        }
    }

    @Override
    public List<DocumentReference> getDocumentsForAuthor(DocumentReference authorReference, int nb, int offset)
        throws AntiSpamException
    {
        return this.antiSpam.getDocumentsForAuthor(authorReference, nb, offset);
    }
}
