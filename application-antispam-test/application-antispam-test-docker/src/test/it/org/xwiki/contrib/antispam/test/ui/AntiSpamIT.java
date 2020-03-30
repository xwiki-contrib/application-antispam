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
package org.xwiki.contrib.antispam.test.ui;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.openqa.selenium.By;
import org.xwiki.administration.test.po.AdministrationPage;
import org.xwiki.antispam.test.po.AntiSpamAdministrationSectionPage;
import org.xwiki.antispam.test.po.AntiSpamHomePage;
import org.xwiki.panels.test.po.ApplicationsPanel;
import org.xwiki.test.docker.junit5.UITest;
import org.xwiki.test.ui.TestUtils;
import org.xwiki.test.ui.XWikiWebDriver;
import org.xwiki.test.ui.po.ViewPage;
import org.xwiki.test.ui.po.editor.WikiEditPage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verify the overall AntiSpam features.
 *
 * @version $Id$
 */
@UITest
public class AntiSpamIT
{
    @Test
    public void verifyAntiSpam(TestUtils setup, TestInfo testInfo, XWikiWebDriver driver) throws Exception
    {
        setup.loginAsSuperAdmin();

        // Make sure that spam checking is active
        AdministrationPage administrationPage = AdministrationPage.gotoPage();
        administrationPage.clickSection("Other", "AntiSpam");
        AntiSpamAdministrationSectionPage asasp = new AntiSpamAdministrationSectionPage();
        asasp.setSpamCheckingActive(true);
        asasp.clickSave();

        // Verify that we can navigate to the AntiSpam app when the user is superadmin
        ApplicationsPanel applicationPanel = ApplicationsPanel.gotoPage();
        applicationPanel.clickApplication("AntiSpam");
        AntiSpamHomePage home = new AntiSpamHomePage();

        // Modify the Keywords file to add the spam keyword that we're going to test.
        // We also test that we can navigate to that page from the AntiSpam home page and that its parent is set ok
        ViewPage vp = home.clickSpamKeywords();
        // Note: we test a regex to verify that regexes work
        WikiEditPage wep = vp.editWiki();
        wep.setContent("hotlin.*");
        vp = wep.clickSaveAndView();
        // Click the breadcrumbs to go back to the home page
        vp.clickBreadcrumbLink("Delete Spam User and Pages");

        // Test that we can navigate to the IPAddresses page from the AntiSpam home page and that its parent is set ok.
        // Note: since we delete this page later in the test, make sure it exists so that we can execute this test
        // several times in a row
        setup.createPage("AntiSpam", "IPAddresses", "", "");
        home = AntiSpamHomePage.gotoPage();
        vp = home.clickBannedIPAddresses();
        // Click the breadcrumbs to go back to the home page
        vp.clickBreadcrumbLink("Delete Spam User and Pages");
        home = new AntiSpamHomePage();

        // Make sure that the Disabled Users page is empty
        // We also test that we can navigate to that page from the AntiSpam home page and that its parent is set ok
        vp = home.clickDisabledSpamUsers();
        wep = vp.editWiki();
        wep.setContent("");
        vp = wep.clickSaveAndView();
        // Click the breadcrumbs to go back to the home page
        vp.clickBreadcrumbLink("Delete Spam User and Pages");

        // Remove the Logs page since we're checking its content below
        setup.deletePage("AntiSpam", "Logs");

        // Try creating spam pages (we should not be able to do that!) as the spam user

        // Create a spam user and log in
        setup.deletePage("XWiki", "spamuser");
        setup.createUserAndLogin("spamuser", "password");

        // Verify that normal users can't access the AntiSpam app.
        applicationPanel = ApplicationsPanel.gotoPage();
        assertFalse(applicationPanel.containsApplication("AntiSpam"), 
            "Applications Panel shouldn't show the AntiSpam entry for non admin users");
        // Verify that if we try to navigate we're redirected to the login action
        setup.gotoPage("AntiSpam", "WebHome");
        assertEquals("You are not allowed to view this page or perform this action.", getErrorMessage(driver));

        // Create a page with some spam in its content (we put the spam content in a multiline to verify multine
        // checking works)
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-in-content");
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-in-content", "line1\ngreat hotline\nline2", 
            "not spam");
        assertTrue(vp.getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-in-content] is considered to be spam"),
            "Got: [" + vp.getErrorContent() + "]");

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        setup.gotoPage("Whatever", "whatever");
        assertTrue(driver.findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the IP address has been logged
        setup.loginAsSuperAdmin();
        vp = setup.gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));

        // Delete the IP page for the next test as otherwise the spam checker would not even check the content!
        setup.deletePage("AntiSpam", "IPAddresses");
        // Re-create the user to continue with the test
        setup.deletePage("XWiki", "spamuser");
        setup.createUserAndLogin("spamuser", "password");

        // Create a page with some spam in its title
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-in-title");
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-in-title", "not spam", "call hotline now!");
        assertTrue(vp.getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-in-title] is considered to be spam"),
            "Got: [" + vp.getErrorContent() + "]");

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        setup.gotoPage("Whatever", "whatever");
        assertTrue(driver.findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the IP address has been logged
        setup.loginAsSuperAdmin();
        vp = setup.gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));

        // Delete the IP page for the next test as otherwise the spam checker would not even check the content!
        setup.deletePage("AntiSpam", "IPAddresses");
        // Re-create the user to continue with the test
        setup.deletePage("XWiki", "spamuser");
        setup.createUserAndLogin("spamuser", "password");

        // Create a page with some spam in the page name
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-hotline");
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-hotline", "not spam", "not spam");
        assertTrue(vp.getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-hotline] is considered to be spam"),
            "Got: [" + vp.getErrorContent() + "]");

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        setup.gotoPage("Whatever", "whatever");
        assertTrue(driver.findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the IP address has been logged
        setup.loginAsSuperAdmin();
        vp = setup.gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));

        // Delete the IP page for the next test as otherwise the spam checker would not even check the content!
        setup.deletePage("AntiSpam", "IPAddresses");
        // Re-create the user to continue with the test
        setup.deletePage("XWiki", "spamuser");
        setup.createUserAndLogin("spamuser", "password");

        // Create a page with some spam in a comment xobject
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-xobject");
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-xobject", "not spam", "not spam");
        setup.addObject(testInfo.getTestClass().get().getName(), "spam-xobject", "XWiki.XWikiComments", "comment",
            "line1\ngreat hotline\nline2");
        assertTrue(vp.getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-xobject] is considered to be spam"),
            "Got: [" + vp.getErrorContent() + "]");

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        setup.gotoPage("Whatever", "whatever");
        assertTrue(driver.findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the matching spam tries have been logged
        setup.loginAsSuperAdmin();
        vp = setup.gotoPage("AntiSpam", "Logs");
        assertEquals("xwiki:AntiSpamTest.spam-in-content - xwiki:XWiki.spamuser - hotline\n"
            + "xwiki:AntiSpamTest.spam-in-title - xwiki:XWiki.spamuser - hotline now!</title>\n"
            + "xwiki:AntiSpamTest.spam-hotline - xwiki:XWiki.spamuser - hotline\" locale=\"\">,hotline</name>\n"
            + "xwiki:AntiSpamTest.spam-xobject - xwiki:XWiki.spamuser - hotline", vp.getContent());

        // Verify that the spam user has been banned and the ip logged
        vp = setup.gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));
        // Remove the IP so that we can navigate to the Admin page below (strangely the admin page does a save)
        wep = vp.editWiki();
        wep.setContent("");
        wep.clickSaveAndContinue();
        vp = setup.gotoPage("AntiSpam", "DisabledUsers");
        assertEquals("xwiki:XWiki.spamuser", vp.getContent());

        // Verify that we can disable the Spam Checking feature. Note that we also need to do this so that the
        // pages we create below do not trigger spam checks... Thus we also verify that spam is no longer caught.
        administrationPage = AdministrationPage.gotoPage();
        administrationPage.clickSection("Other", "AntiSpam");
        asasp = new AntiSpamAdministrationSectionPage();
        asasp.setSpamCheckingActive(false);
        asasp.clickSave();

        // Step 2: We verify the spam cleaning feature

        // Delete pages as superadmin user
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-in-content");
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-in-title");
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-hotline");
        setup.deletePage(testInfo.getTestClass().get().getName(), "spam-xobject");

        // Log in as the spam user
        // Re-create the user to continue with the test
        setup.deletePage("XWiki", "spamuser");
        setup.createUserAndLogin("spamuser", "password");

        // Create a page with some spam in its content (we put the spam content in a multiline to verify multine
        // checking works)
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-in-content", "line1\ngreat hotline\nline2",
            "not spam");
        // Create a page with some spam in its title
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-in-title", "not spam", "call hotline now!");
        // Create a page with some spam in the page name
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-hotline", "not spam", "not spam");
        // Create a page with some spam in a comment xobject
        setup.createPage(testInfo.getTestClass().get().getName(), "spam-xobject", "not spam", "not spam");
        setup.addObject(testInfo.getTestClass().get().getName(), "spam-xobject", "XWiki.XWikiComments", "comment",
            "line1\ngreat hotline\nline2");

        // Let's create a page without spam but created by the spamuser to verify it's listed in the related pages
        // below.
        setup.createPage(testInfo.getTestClass().get().getName(), "relatedpage", "no spam in it", "relatedpage");

        // Log in as superadmin
        setup.loginAsSuperAdmin();

        // Search for a spam keyword and verify the results
        home = AntiSpamHomePage.gotoPage();
        home = home.searchSpam("hotline");
        // Verify the Matched Pages
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-hotline"));
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-in-title"));
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-xobject"));
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-in-content"));
        // Verify the Matched Authors
        assertEquals("xwiki:XWiki.spamuser", home.getMatchedAuthorsText());
        // Verify the Matched Related Pages
        assertEquals("xwiki:AntiSpamTest.relatedpage", home.getMatchedRelatedPagesText());
        // Verify the Matched Activity Stream
        List<String> asTexts = Arrays.asList(StringUtils.split(home.getMatchedActivityStreamText(), "\n "));
        assertTrue(asTexts.size() >= 7);

        // Press "Delete" to clean the spam and press "Confirm Delete"
        home = home.deleteSpam().confirmDeleteSpam();

        // Verify that the Spam pages have been deleted
        assertFalse(setup.pageExists("XWiki", "spamuser"));
        assertFalse(setup.pageExists(testInfo.getTestClass().get().getName(), "spam-in-content"));
        assertFalse(setup.pageExists(testInfo.getTestClass().get().getName(), "spam-in-title"));
        assertFalse(setup.pageExists(testInfo.getTestClass().get().getName(), "spam-hotline"));
        assertFalse(setup.pageExists(testInfo.getTestClass().get().getName(), "spam-xobject"));

        // Click Search again to ensure everything's been deleted
        home = home.searchSpam("hotline");
        assertNull(home.getMatchedPagesText());
        assertNull(home.getMatchedAuthorsText());
        assertNull(home.getMatchedRelatedPagesText());
        assertNull(home.getMatchedActivityStreamText());

    }

    public String getErrorMessage(XWikiWebDriver driver)
    {
        return driver.findElementWithoutWaiting(
            By.xpath("//div[@id = 'mainContentArea']//div[contains(@class, 'panel-body')]/p")).getText();
    }
}
