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

import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.FindBy;
import org.xwiki.test.ui.po.ViewPage;

/**
 * Represents the Home page of the AntiSpam application.
 *
 * @version $Id$
 */
public class AntiSpamHomePage extends ViewPage
{
    @FindBy(xpath = "//input[@name = 'query']")
    private WebElement searchInput;

    @FindBy(xpath = "//input[@name = 'searchSpam']")
    private WebElement searchSubmit;

    @FindBy(xpath = "//input[@name = 'findInactiveUsers']")
    private WebElement findInactiveUsersSubmit;

    @FindBy(xpath = "//input[@name = 'delete']")
    private WebElement deleteSubmit;

    @FindBy(xpath = "//input[@name = 'confirmDelete']")
    private WebElement confirmDeleteSubmit;

    @FindBy(xpath = "//a[text() = 'Spam Keywords']")
    private WebElement keywordsLink;

    @FindBy(xpath = "//a[text() = 'Banned IP Addresses']")
    private WebElement bannedIPAddressesLink;

    @FindBy(xpath = "//a[text() = 'Disabled Spam Users']")
    private WebElement disabledSpamUsersLink;

    public static AntiSpamHomePage gotoPage()
    {
        getUtil().gotoPage("AntiSpam", "WebHome");
        return new AntiSpamHomePage();
    }

    public ViewPage clickSpamKeywords()
    {
        return clickAndWait(this.keywordsLink);
    }

    public ViewPage clickBannedIPAddresses()
    {
        return clickAndWait(this.bannedIPAddressesLink);
    }

    public ViewPage clickDisabledSpamUsers()
    {
        return clickAndWait(this.disabledSpamUsersLink);
    }

    private ViewPage clickAndWait(WebElement element)
    {
        // TODO: Override the default timeout because by default it's 10seconds and we click on links that lead to pages
        // containing the {{code}} macro which initialize jython on the first load and that init can take more than
        // 10 seconds. Without this override, the waitUntilPageIsReloaded() would fail.
        // Note that we set a large timeout (hence the * 10) because we noticed sometimes large delays locally when
        // testing inside docker containers (got up to 50s of delays once).
        int timeout = getDriver().getTimeout();
        getDriver().setTimeout(timeout * 10);
        try {
            // TODO: Seems that sel3's click() doesn't wait anymore.
            // This seems related to https://github.com/mozilla/geckodriver/issues/1026 but here we're not clicking
            // the submit of a form.
            getDriver().addPageNotYetReloadedMarker();
            element.click();
            getDriver().waitUntilPageIsReloaded();
            return new ViewPage();
        } finally {
            getDriver().setTimeout(timeout);
        }
    }

    public AntiSpamHomePage searchSpam(String keyword)
    {
        // Make sure the element is visible. Apparently this is important to be able to click on the form.
        // Note: using getDriver().scrollTo(this.searchInput) didn't work
        scrollIntoView(this.searchInput);
        this.searchInput.clear();;
        this.searchInput.sendKeys(keyword);
        // TODO: Remove once https://github.com/mozilla/geckodriver/issues/1026 is fixed
        getDriver().addPageNotYetReloadedMarker();
        this.searchSubmit.click();
        getDriver().waitUntilPageIsReloaded();
        return new AntiSpamHomePage();
    }

    public AntiSpamHomePage deleteSpam()
    {
        this.deleteSubmit.click();
        return new AntiSpamHomePage();
    }

    public AntiSpamHomePage confirmDeleteSpam()
    {
        this.confirmDeleteSubmit.click();
        return new AntiSpamHomePage();
    }

    public String getMatchedPagesText()
    {
        return getText("//h2[@id = 'HMatchingPages']/following-sibling::ul");
    }

    public String getMatchedAuthorsText()
    {
        return getText("//h2[@id = 'HAuthors']/following-sibling::ul");
    }

    public String getMatchedRelatedPagesText()
    {
        return getText("//h2[@id = 'HRelatedPages']/following-sibling::ul");
    }

    public String getMatchedActivityStreamText()
    {
        return getText("//form[@id = 'events']/div");
    }

    public AntiSpamInactiveUsersPage clickFindInactiveUsers()
    {
        this.findInactiveUsersSubmit.click();
        return new AntiSpamInactiveUsersPage();
    }

    private String getText(String xpath)
    {
        By by = By.xpath(xpath);
        if (getDriver().hasElementWithoutWaiting(by)) {
            return getDriver().findElementWithoutWaiting(by).getText();
        } else {
            return null;
        }
    }

    private void scrollIntoView(WebElement element)
    {
        if (!isVisibleInViewport(element)) {
            Actions actions = new Actions(getDriver());
            actions.moveToElement(element).build().perform();
        }
    }

    private boolean isVisibleInViewport(WebElement element)
    {
        // See https://stackoverflow.com/questions/60562711/selenium-scroll-into-view-doesnt-work-when-element-is-already-into-view
        return (Boolean)((JavascriptExecutor) getDriver()).executeScript(
            "var elem = arguments[0],                 "
                + "  box = elem.getBoundingClientRect(),    "
                + "  cx = box.left + box.width / 2,         "
                + "  cy = box.top + box.height / 2,         "
                + "  e = document.elementFromPoint(cx, cy); "
                + "for (; e; e = e.parentElement) {         "
                + "  if (e === elem)                        "
                + "    return true;                         "
                + "}                                        "
                + "return false;                            "
            , element);
    }
}
