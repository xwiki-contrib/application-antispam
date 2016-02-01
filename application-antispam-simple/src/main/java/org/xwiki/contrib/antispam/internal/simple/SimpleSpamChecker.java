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
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.antispam.AntiSpamException;
import org.xwiki.contrib.antispam.SpamChecker;

@Component
@Named("simple")
@Singleton
public class SimpleSpamChecker implements SpamChecker
{
    private static final String IP_PARAMETER = "ip";

    @Inject
    private SpamCheckerModel model;

    @Override
    public boolean isSpam(Reader content, Map<String, Object> parameters) throws AntiSpamException
    {
        // Step 1: Check for known IP addresses of spammers. Consider that all content created by a spammer ip to
        //             be spam.
        String ip = (String) parameters.get(IP_PARAMETER);
        if (ip != null) {
            if (this.model.getSpamAddresses().contains(ip)) {
                return true;
            }
        }

        // Step 2: Check for known spam keywords in the content
        try {
            String contentAsString = IOUtils.toString(content);
            List<String> keywords = this.model.getSpamKeywords();
            if (!keywords.isEmpty()) {
                String regex = String.format("(?s)(?i)^.*?(%s).*$", StringUtils.join(keywords, '|'));
                if (contentAsString.matches(regex)) {
                    return true;
                }
            }
        } catch (Exception e) {
            throw new AntiSpamException("Error checking for spam keywords", e);
        }

        return false;
    }
}
