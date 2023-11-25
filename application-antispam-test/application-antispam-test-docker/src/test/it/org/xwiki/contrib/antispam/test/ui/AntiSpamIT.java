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
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.xwiki.administration.test.po.AdministrationPage;
import org.xwiki.antispam.test.po.AntiSpamAdministrationSectionPage;
import org.xwiki.antispam.test.po.AntiSpamHomePage;
import org.xwiki.antispam.test.po.AntiSpamInactiveUsersPage;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.panels.test.po.ApplicationsPanel;
import org.xwiki.rest.model.jaxb.Page;
import org.xwiki.test.docker.junit5.TestReference;
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
@UITest(
    extraJARs = {
        // The Solr store is not ready yet to be installed as an extension, so we need to add it to WEB-INF/lib
        // manually. See https://jira.xwiki.org/browse/XWIKI-21594
        "org.xwiki.platform:xwiki-platform-eventstream-store-solr",
        // Because of https://jira.xwiki.org/browse/XWIKI-17972 we need to install the jython jar manually in
        // WEB-INF/lib.
        //"org.python:jython-slim:2.7.3"
    },
    resolveExtraJARs = true
)
class AntiSpamIT
{
    @Test
    @Order(1)
    void verifyHomePageFeatures(TestUtils setup, TestReference testReference, XWikiWebDriver driver) throws Exception
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
        SpaceReference baseReference = testReference.getLastSpaceReference();
        DocumentReference spamInContentReference = new DocumentReference("spam-in-content", baseReference);
        setup.deletePage(spamInContentReference);
        setup.createPage(spamInContentReference, "line1\ngreat hotline\nline2", "not spam");
        assertTrue(vp.getErrorContent().contains("The content of [" + spamInContentReference
            + "] is considered to be spam"), "Got: [" + vp.getErrorContent() + "]");

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
        DocumentReference spamInTitleReference = new DocumentReference("spam-in-title", baseReference);
        setup.deletePage(spamInTitleReference);
        setup.createPage(spamInTitleReference, "not spam", "call hotline now!");
        assertTrue(vp.getErrorContent().contains("The content of [" + spamInTitleReference
            + "] is considered to be spam"), "Got: [" + vp.getErrorContent() + "]");

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
        DocumentReference spamHotlineReference = new DocumentReference("spam-hotline", baseReference);
        setup.deletePage(spamHotlineReference);
        setup.createPage(spamHotlineReference, "not spam", "not spam");
        assertTrue(vp.getErrorContent().contains("The content of [" + spamHotlineReference
            + "] is considered to be spam"), "Got: [" + vp.getErrorContent() + "]");

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
        DocumentReference spamXObjectReference = new DocumentReference("spam-xobject", baseReference);
        setup.deletePage(spamXObjectReference);
        setup.createPage(spamXObjectReference, "not spam", "not spam");
        setup.addObject(spamXObjectReference, "XWiki.XWikiComments", "comment", "line1\ngreat hotline\nline2");
        assertTrue(vp.getErrorContent().contains("The content of [" + spamXObjectReference
            + "] is considered to be spam"), "Got: [" + vp.getErrorContent() + "]");

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        setup.gotoPage("Whatever", "whatever");
        assertTrue(driver.findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the matching spam tries have been logged
        setup.loginAsSuperAdmin();
        vp = setup.gotoPage("AntiSpam", "Logs");
        assertEquals(spamInContentReference  +" - xwiki:XWiki.spamuser - hotline\n"
            + spamInTitleReference + " - xwiki:XWiki.spamuser - hotline now!</title>\n"
            + spamHotlineReference + " - xwiki:XWiki.spamuser - hotline\" locale=\"\">,hotline</name>\n"
            + spamXObjectReference + " - xwiki:XWiki.spamuser - hotline", vp.getContent());

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
        // pages we create below do not trigger spam checks... Thus, we also verify that spam is no longer caught.
        administrationPage = AdministrationPage.gotoPage();
        administrationPage.clickSection("Other", "AntiSpam");
        asasp = new AntiSpamAdministrationSectionPage();
        asasp.setSpamCheckingActive(false);
        asasp.clickSave();

        // Step 2: We verify the spam cleaning feature

        // Delete pages as superadmin user
        setup.deletePage(spamInContentReference);
        setup.deletePage(spamInTitleReference);
        setup.deletePage(spamHotlineReference);
        setup.deletePage(spamXObjectReference);

        // Log in as the spam user
        // Re-create the user to continue with the test
        setup.deletePage("XWiki", "spamuser");
        setup.createUserAndLogin("spamuser", "password");

        // Create a page with some spam in its content (we put the spam content in a multiline to verify multiline
        // checking works)
        setup.createPage(spamInContentReference, "line1\ngreat hotline\nline2", "not spam");
        // Create a page with some spam in its title
        setup.createPage(spamInTitleReference, "not spam", "call hotline now!");
        // Create a page with some spam in the page name
        setup.createPage(spamHotlineReference, "not spam", "not spam");
        // Create a page with some spam in a comment xobject
        setup.createPage(spamXObjectReference, "not spam", "not spam");
        setup.addObject(spamXObjectReference, "XWiki.XWikiComments", "comment", "line1\ngreat hotline\nline2");

        // Let's create a page without spam but created by the spamuser to verify it's listed in the related pages
        // below.
        DocumentReference relatedReference = new DocumentReference("relatedpage", baseReference);
        setup.createPage(relatedReference, "no spam in it", "relatedpage");

        // Log in as superadmin
        setup.loginAsSuperAdmin();

        // Modify a document with spam to verify that we don't try to remove that modification since it comes from
        // a user having admin rights + verify that the UI shows that the superadmin user won't be removed
        Page page = setup.rest().page(spamInContentReference);
        // We keep the old content (with the spam that the admin user has not seen) + add new content
        page.setContent("new content by admin user\n" + "line1\ngreat hotline\nline2");
        setup.rest().save(page, 202);

        // Search for a spam keyword and verify the results
        home = AntiSpamHomePage.gotoPage();
        home = home.searchSpam("hotline");
        // Verify the Matched Pages
        assertTrue(home.getMatchedPagesText().contains(spamHotlineReference.toString()));
        assertTrue(home.getMatchedPagesText().contains(spamInTitleReference.toString()));
        assertTrue(home.getMatchedPagesText().contains(spamXObjectReference.toString()));
        assertTrue(home.getMatchedPagesText().contains(spamInContentReference.toString()));
        // Verify the Matched Authors
        assertEquals("xwiki:XWiki.spamuser\nxwiki:XWiki.superadmin Excluded for safety since it has Admin access to"
            +" this page", home.getMatchedAuthorsText());
        // Verify the Matched Related Pages
        assertEquals("xwiki:XWiki.spamuser\n"
            + spamInTitleReference + "\n"
            + spamHotlineReference + "\n"
            + spamXObjectReference + "\n"
            + relatedReference + "\n"
            + spamInContentReference, home.getMatchedRelatedPagesText());
        // Verify the Matched Activity Stream
        List<String> asTexts = Arrays.asList(StringUtils.split(home.getMatchedActivityStreamText(), "\n "));
        assertTrue(asTexts.size() >= 7);

        // Press "Delete" to clean the spam and press "Confirm Delete"
        home.deleteSpam().confirmDeleteSpam();

        // Verify that the Spam pages have been deleted
        assertFalse(setup.pageExists("XWiki", "spamuser"));
        assertFalse(setup.rest().exists(spamInTitleReference));
        assertFalse(setup.rest().exists(spamHotlineReference));
        assertFalse(setup.rest().exists(spamXObjectReference));

        // Verify that "spam-in-content" page still exists since a new revision has been created above by the superadmin
        // user but that revision 1.1 is gone.
        assertTrue(setup.rest().exists(spamInContentReference));
        setup.gotoPage(spamInContentReference, "viewrev", "rev=1.1");
        vp = new ViewPage();
        assertEquals("", vp.getContent());

        // Click Search again to ensure everything's been deleted
        home = AntiSpamHomePage.gotoPage();
        home = home.searchSpam("hotline");
        assertEquals(spamInContentReference + " This change was made by [xwiki:XWiki.superadmin] and won't be"
            + " removed since it's an Admin!", home.getMatchedPagesText());
        assertEquals("xwiki:XWiki.superadmin Excluded for safety since it has Admin access to this page",
            home.getMatchedAuthorsText());
        assertNull(home.getMatchedRelatedPagesText());
        assertNull(home.getMatchedActivityStreamText());
    }

    @Test
    @Order(2)
    void verifyInactiveUserCleaning(TestUtils setup, TestReference testReference, XWikiWebDriver driver)
    {
        setup.loginAsSuperAdmin();

        // Create a user profile page with a date in the past so that it's considered inactive.
        setup.createUser("InactiveUser", "pass", null);
        // Note: the content requires PR, so we need to exclude it for the PR checker in the pom.xml
        SpaceReference baseReference = testReference.getLastSpaceReference();
        DocumentReference tmpReference = new DocumentReference("InactiveUserSetup", baseReference);
        setup.createPage(tmpReference, "{{velocity}}\n"
            + "#set ($calendar = $datetool.systemCalendar)\n"
            + "#set ($discard = $calendar.add(5, -60))\n"
            + "#set ($oldDate = $calendar.time)\n"
            + "\n"
            + "#set ($mydoc = $xwiki.getDocument('XWiki.InactiveUser'))\n"
            + "#set ($discard = $mydoc.document.setDate($oldDate))\n"
            + "\n"
            + "## Prevents XWiki from setting the current date on save.\n"
            + "## Note that it'll also not create a new revision\n"
            + "#set ($discard = $mydoc.document.setContentDirty(false))\n"
            + "#set ($discard = $mydoc.document.setMetaDataDirty(false))\n"
            + "\n"
            + "#set ($discard = $mydoc.save())\n"
            + "{{/velocity}}", "");
        AntiSpamHomePage homePage = AntiSpamHomePage.gotoPage();
        AntiSpamInactiveUsersPage aiup = homePage.clickFindInactiveUsers();
        List<String> users = aiup.getInactiveUsers();
        assertEquals(1, users.size());
        assertEquals("xwiki:XWiki.InactiveUser", users.get(0));

        // Clean the inactive user
        aiup.clickCleanInactiveUsers();

        // TODO: Wait for the job to finish. We cannot ATM since the job UI doesn't display correctly. This needs to
        // be fixed. Once it is, wait for the job to finish and go to the AntiSpamInactiveUsersPage page again and
        // verify there's the message that no inactive user is found.
    }

    private String getErrorMessage(XWikiWebDriver driver)
    {
        return driver.findElementWithoutWaiting(
            By.xpath("//div[@id = 'mainContentArea']//div[contains(@class, 'panel-body')]/p")).getText();
    }
}
