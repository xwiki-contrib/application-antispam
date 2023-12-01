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

import java.util.Map;

import static java.util.Collections.emptyMap;

/**
 * Represents the result of a spam check.
 *
 * @version $Id$
 * @since 1.10
 */
public class SpamCheckerResult
{
    private boolean isSpam;

    private Map<String, String> matchedContent;

    /**
     * @param isSpam whether the content is spam or not
     */
    public SpamCheckerResult(boolean isSpam)
    {
        this(isSpam, emptyMap());
    }

    /**
     * @param isSpam whether the content is spam or not
     * @param matchedContent the keywords matched along with some contextual information
     */
    public SpamCheckerResult(boolean isSpam, Map<String, String> matchedContent)
    {
        this.isSpam = isSpam;
        this.matchedContent = matchedContent;
    }

    /**
     * @return whether the content is spam or not
     */
    public boolean isSpam()
    {
        return this.isSpam;
    }

    /**
     * @return the keywords matched along with some contextual information
     */
    public Map<String, String> getMatchedContent()
    {
        return this.matchedContent;
    }
}
