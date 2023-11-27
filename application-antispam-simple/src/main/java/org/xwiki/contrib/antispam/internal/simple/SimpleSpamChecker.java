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

import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.contrib.antispam.SpamChecker;
import org.xwiki.model.reference.DocumentReference;

@Component
@Named("simple")
@Singleton
public class SimpleSpamChecker implements SpamChecker
{
    private static final String IP_PARAMETER = "ip";

    private static final String AUTHOR_PARAMETER = "authorReference";

    private static final String DOCUMENT_PARAMETER = "documentReference";

    @Inject
    private SpamCheckerModel model;

    @Override
    public boolean isSpam(Reader content, Map<String, Object> parameters) throws AntiSpamException
    {
        // Step 1: Check for known IP addresses of spammers. Consider that all content created by a spammer ip to
        //         be spam. Don't consider the guest user a spammer just based on its IP address (only consider it a
        //         spammer if it also matches a spam keywords. This is because at startup XWiki tries to save some
        //         documents with the guest user (e.g. a scheduler job can have its status updated), and we don't
        //         want to prevent this from working.
        DocumentReference authorReference = (DocumentReference) parameters.get(AUTHOR_PARAMETER);
        String ip = (String) parameters.get(IP_PARAMETER);
        if (ip != null && authorReference != null && this.model.getSpamAddresses().contains(ip)) {
            return true;
        }

        // Step 2: Check for known spam keywords in the passed content (which should include page name and page title)
        try {
            String contentAsString = IOUtils.toString(content);
            List<String> keywords = this.model.getSpamKeywords();
            if (!keywords.isEmpty()) {
                String regex = StringUtils.join(keywords, '|');
                Pattern pattern = Pattern.compile(regex);
                Matcher matcher = pattern.matcher(contentAsString);
                List<String> matchedKeywords = new ArrayList<>();
                while (matcher.find()) {
                    matchedKeywords.add(matcher.group());
                }
                if (!matchedKeywords.isEmpty()) {
                    DocumentReference documentReference = (DocumentReference) parameters.get(DOCUMENT_PARAMETER);
                    if (authorReference != null && documentReference != null) {
                        this.model.logMatchingSpamKeywords(matchedKeywords, authorReference, documentReference);
                    }
                    return true;
                }
            }
        } catch (Exception e) {
            throw new AntiSpamException("Error checking for spam keywords", e);
        }

        return false;
    }
}
