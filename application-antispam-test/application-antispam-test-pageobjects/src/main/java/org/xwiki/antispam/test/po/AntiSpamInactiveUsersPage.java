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
package org.xwiki.antispam.test.po;

import java.util.ArrayList;
import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;
import org.xwiki.test.ui.po.ViewPage;

/**
 * Represents the {@code AntiSpam.CleanInactiveUsers} page.
 *
 * @version $Id$
 */
public class AntiSpamInactiveUsersPage extends ViewPage
{
    @FindBy(xpath = "//input[@name = 'deleteInactiveUsers']")
    private WebElement cleanInactiveUsersSubmit;

    public static AntiSpamInactiveUsersPage gotoPage()
    {
        getUtil().gotoPage("AntiSpam", "CleanInactiveUsers");
        return new AntiSpamInactiveUsersPage();
    }

    public List<String> getInactiveUsers()
    {
        List<String> users = new ArrayList<>();
        for (WebElement element :
            getDriver().findElements(By.xpath("//p[text() = 'Inactive users (max 50):']/following-sibling::ul/li")))
        {
            users.add(element.getText());
        }
        return users;
    }

    public void clickCleanInactiveUsers()
    {
        this.cleanInactiveUsersSubmit.click();
    }
}
