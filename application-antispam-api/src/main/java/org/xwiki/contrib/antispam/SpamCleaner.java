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

import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;

@Role
public interface SpamCleaner
{
    /**
     * Get references and last authors of all documents matching a given solr query string.
     *
     * @param solrQueryString the solr query string to search with (e.g. "mcafee")
     * @param nb the number of matching results to return
     * @param offset the start position in the full list of matching results
     * @return the list of references of matching documents and their last authors
     * @exception AntiSpamException if an error occurs such as a failure to find matching documents
     */
    List<MatchingReference> getMatchingDocuments(String solrQueryString, int nb, int offset) throws AntiSpamException;

    /**
     * Clean the passed documents of all changes made by the passed authors.
     *
     * @param documentReference the reference to the document to clean
     * @param authorReferences the reference to the authors for which to remove all changes from the document
     * @param skipActivityStream if true then don't generate events in the Activity Stream for the changes made to
     *        the document
     * @exception AntiSpamException if an error occurs
     */
    void cleanDocument(DocumentReference documentReference, Collection<DocumentReference> authorReferences,
        boolean skipActivityStream) throws AntiSpamException;

    /**
     * Find all documents with the passed author.
     *
     * @param authorReference the author for which to return the list of modified documents (i.e the last author of
     *        the returned documents)
     * @param nb the number of results to return
     * @param offset the start position in the full list of results
     * @return the list of references to documents for which the passed author was the last author
     * @exception AntiSpamException if an error occurs
     */
    List<DocumentReference> getDocumentsForAuthor(DocumentReference authorReference, int nb, int offset)
        throws AntiSpamException;

    /**
     * Find all user references for the following criterias:
     * <ul>
     *   <li>The user profile page jas been created more than elapsedDays ago</li>
     *   <li>The user profile page doesn't have an avatar (if cleanAuthorsWithAvatars is false)</li>
     *   <li>The user profile page doesn't have an XObject of type XWiki.OIDC.ConsentClass. The reason for this check
     *     is because we can have users who create users on xwiki.org just to be able to log on forum.xwiki.org for
     *     example (or on l10n.xwiki.org). We don't want to consider these users as inactive and remove their
     *     accounts or they won't be able to log on these other sites...</li>
     * </ul>
     *
     * @param elapsedDays number of days that the user profile page has seen a modification
     * @param cleanAuthorsWithAvatars if true then also clean user profiles having an avatar set
     * @param count the maximum number of inactive user references to return
     * @return the inactive author references
     * @throws AntiSpamException if an error occurs
     * @since 1.8
     */
    List<DocumentReference> getInactiveAuthors(int elapsedDays, boolean cleanAuthorsWithAvatars, int count)
        throws AntiSpamException;

    /**
     * @return all the known users, i.e. users that should not be cleaned and that should be filtered out when listing
     *         filtered changes
     * @throws AntiSpamException if an error occurs
     * @since 1.8
     */
    Set<DocumentReference> getKnownUserReferences() throws AntiSpamException;
}
