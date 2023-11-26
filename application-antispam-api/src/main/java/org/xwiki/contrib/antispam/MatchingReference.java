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

import org.xwiki.model.reference.DocumentReference;

/**
 * A reference matching a spam query. Contains a reference to the matching document and its last author reference.
 *
 * @version $Id$
 * @since 1.8
 */
public class MatchingReference
{
    private DocumentReference documentReference;

    private DocumentReference lastAuthorReference;

    /**
     *
     * @param documentReference the reference to the document containing spam
     * @param lastAuthorReference the reference to the last author of the document
     */
    public MatchingReference(DocumentReference documentReference, DocumentReference lastAuthorReference)
    {
        this.documentReference = documentReference;
        this.lastAuthorReference = lastAuthorReference;
    }

    /**
     * @return the reference to the document containing spam
     */
    public DocumentReference getDocumentReference()
    {
        return this.documentReference;
    }

    /**
     * @return the reference to the last author of the document
     */
    public DocumentReference getLastAuthorReference()
    {
        return this.lastAuthorReference;
    }
}
