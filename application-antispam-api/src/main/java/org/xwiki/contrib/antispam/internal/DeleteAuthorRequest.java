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
package org.xwiki.contrib.antispam.internal;

import java.util.List;

import org.xwiki.job.AbstractRequest;
import org.xwiki.model.reference.DocumentReference;

/**
 * Request to delete authors.
 *
 * @version $Id$
 */
public class DeleteAuthorRequest extends AbstractRequest
{
    private static final String AUTHOR_REFERENCES = "authorReferences";

    private static final String SKIP_EVENTSTREAM_RECORDING = "skipEventStreamRecording";

    public void setAuthorReferences(List<DocumentReference> authorReferences)
    {
        setProperty(AUTHOR_REFERENCES, authorReferences);
    }

    public List<DocumentReference> getAuthorReferences()
    {
        return getProperty(AUTHOR_REFERENCES);
    }

    public void setSkipEventStream(boolean skipEventStream)
    {
        setProperty(SKIP_EVENTSTREAM_RECORDING, skipEventStream);
    }

    public boolean skipEventStreamRecording()
    {
        return getProperty(SKIP_EVENTSTREAM_RECORDING);
    }
}
