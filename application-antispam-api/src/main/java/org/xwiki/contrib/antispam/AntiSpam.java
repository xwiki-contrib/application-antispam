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

import org.apache.commons.lang3.tuple.Pair;
import org.xwiki.component.annotation.Role;
import org.xwiki.model.reference.DocumentReference;

@Role
public interface AntiSpam
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
    Pair<List<DocumentReference>, Set<DocumentReference>> getMatchingDocuments(String solrQueryString, int nb,
        int offset) throws AntiSpamException;

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
}
