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
import org.junit.*;
import org.openqa.selenium.By;
import org.xwiki.administration.test.po.AdministrationPage;
import org.xwiki.antispam.test.po.AntiSpamAdministrationSectionPage;
import org.xwiki.antispam.test.po.AntiSpamHomePage;
import org.xwiki.antispam.test.po.AntiSpamInactiveUsersPage;
import org.xwiki.panels.test.po.ApplicationsPanel;
import org.xwiki.rest.model.jaxb.Page;
import org.xwiki.test.ui.AbstractTest;
import org.xwiki.test.ui.SuperAdminAuthenticationRule;
import org.xwiki.test.ui.po.ViewPage;
import org.xwiki.test.ui.po.editor.WikiEditPage;

import static org.junit.Assert.*;

/**
 * Verify the overall AntiSpam features.
 *
 * @version $Id$
 */
public class AntiSpamTest extends AbstractTest
{
    @Rule
    public SuperAdminAuthenticationRule authenticationRule = new SuperAdminAuthenticationRule(getUtil());

    @Test
    public void verifyAntiSpam() throws Exception
    {
        //verifyHomePageFeatures();
        verifyInactiveUserCleaning();
    }

    public void verifyHomePageFeatures() throws Exception
    {
        // Step 1: We verify the spam checking feature

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
        getUtil().createPage("AntiSpam", "IPAddresses", "", "");
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
        getUtil().deletePage("AntiSpam", "Logs");

        // Try creating spam pages (we should not be able to do that!) as the spam user

        // Create a spam user and log in
        getUtil().deletePage("XWiki", "spamuser");
        getUtil().createUserAndLogin("spamuser", "password");

        // Verify that normal users can't access the AntiSpam app.
        applicationPanel = ApplicationsPanel.gotoPage();
        assertFalse("Applications Panel shouldn't show the AntiSpam entry for non admin users",
            applicationPanel.containsApplication("AntiSpam"));
        // Verify that if we try to navigate we're redirected to the login action
        getUtil().gotoPage("AntiSpam", "WebHome");
        assertEquals("You are not allowed to view this page or perform this action.", getErrorMessage());

        // Create a page with some spam in its content (we put the spam content in a multiline to verify multine
        // checking works)
        getUtil().deletePage(getTestClassName(), "spam-in-content");
        getUtil().createPage(getTestClassName(), "spam-in-content", "line1\ngreat hotline\nline2", "not spam");
        assertTrue("Got: [" + getErrorContent() + "]", getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-in-content] is considered to be spam"));

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        getUtil().gotoPage("Whatever", "whatever");
        assertTrue(getDriver().findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the IP address has been logged
        this.authenticationRule.authenticate();
        vp = getUtil().gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));

        // Delete the IP page for the next test as otherwise the spam checker would not even check the content!
        getUtil().deletePage("AntiSpam", "IPAddresses");
        // Re-create the user to continue with the test
        getUtil().deletePage("XWiki", "spamuser");
        getUtil().createUserAndLogin("spamuser", "password");

        // Create a page with some spam in its title
        getUtil().deletePage(getTestClassName(), "spam-in-title");
        getUtil().createPage(getTestClassName(), "spam-in-title", "not spam", "call hotline now!");
        assertTrue("Got: [" + getErrorContent() + "]", getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-in-title] is considered to be spam"));

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        getUtil().gotoPage("Whatever", "whatever");
        assertTrue(getDriver().findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the IP address has been logged
        this.authenticationRule.authenticate();
        vp = getUtil().gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));

        // Delete the IP page for the next test as otherwise the spam checker would not even check the content!
        getUtil().deletePage("AntiSpam", "IPAddresses");
        // Re-create the user to continue with the test
        getUtil().deletePage("XWiki", "spamuser");
        getUtil().createUserAndLogin("spamuser", "password");

        // Create a page with some spam in the page name
        getUtil().deletePage(getTestClassName(), "spam-hotline");
        getUtil().createPage(getTestClassName(), "spam-hotline", "not spam", "not spam");
        assertTrue("Got: [" + getErrorContent() + "]", getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-hotline] is considered to be spam"));

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        getUtil().gotoPage("Whatever", "whatever");
        assertTrue(getDriver().findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the IP address has been logged
        this.authenticationRule.authenticate();
        vp = getUtil().gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));

        // Delete the IP page for the next test as otherwise the spam checker would not even check the content!
        getUtil().deletePage("AntiSpam", "IPAddresses");
        // Re-create the user to continue with the test
        getUtil().deletePage("XWiki", "spamuser");
        getUtil().createUserAndLogin("spamuser", "password");

        // Create a page with some spam in a comment xobject
        getUtil().deletePage(getTestClassName(), "spam-xobject");
        getUtil().createPage(getTestClassName(), "spam-xobject", "not spam", "not spam");
        getUtil().addObject(getTestClassName(), "spam-xobject", "XWiki.XWikiComments", "comment",
            "line1\ngreat hotline\nline2");
        assertTrue("Got: [" + getErrorContent() + "]", getErrorContent().contains(
            "The content of [xwiki:AntiSpamTest.spam-xobject] is considered to be spam"));

        // Verify that the user is disabled (navigate to a page and verify it cannot be viewed)
        getUtil().gotoPage("Whatever", "whatever");
        assertTrue(getDriver().findElementWithoutWaiting(By.className("xwikimessage")).getText().contains(
            "Your account has been disabled"));

        // Verify that the matching spam tries have been logged
        this.authenticationRule.authenticate();
        vp = getUtil().gotoPage("AntiSpam", "Logs");
        assertEquals("xwiki:AntiSpamTest.spam-in-content - xwiki:XWiki.spamuser - hotline\n"
            + "xwiki:AntiSpamTest.spam-in-title - xwiki:XWiki.spamuser - hotline now!</title>\n"
            + "xwiki:AntiSpamTest.spam-hotline - xwiki:XWiki.spamuser - hotline\" locale=\"\">,hotline</name>\n"
            + "xwiki:AntiSpamTest.spam-xobject - xwiki:XWiki.spamuser - hotline", vp.getContent());

        // Verify that the spam user has been banned and the ip logged
        vp = getUtil().gotoPage("AntiSpam", "IPAddresses");
        assertTrue(StringUtils.isNotEmpty(vp.getContent()));
        // Remove the IP so that we can navigate to the Admin page below (strangely the admin page does a save)
        wep = vp.editWiki();
        wep.setContent("");
        wep.clickSaveAndContinue();
        vp = getUtil().gotoPage("AntiSpam", "DisabledUsers");
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
        getUtil().deletePage(getTestClassName(), "spam-in-content");
        getUtil().deletePage(getTestClassName(), "spam-in-title");
        getUtil().deletePage(getTestClassName(), "spam-hotline");
        getUtil().deletePage(getTestClassName(), "spam-xobject");

        // Log in as the spam user
        // Re-create the user to continue with the test
        getUtil().deletePage("XWiki", "spamuser");
        getUtil().createUserAndLogin("spamuser", "password");

        // Create a page with some spam in its content (we put the spam content in a multiline to verify multine
        // checking works)
        getUtil().createPage(getTestClassName(), "spam-in-content", "line1\ngreat hotline\nline2", "not spam");
        // Create a page with some spam in its title
        getUtil().createPage(getTestClassName(), "spam-in-title", "not spam", "call hotline now!");
        // Create a page with some spam in the page name
        getUtil().createPage(getTestClassName(), "spam-hotline", "not spam", "not spam");
        // Create a page with some spam in a comment xobject
        getUtil().createPage(getTestClassName(), "spam-xobject", "not spam", "not spam");
        getUtil().addObject(getTestClassName(), "spam-xobject", "XWiki.XWikiComments", "comment",
            "line1\ngreat hotline\nline2");

        // Let's create a page without spam but created by the spamuser to verify it's listed in the related pages
        // below.
        getUtil().createPage(getTestClassName(), "relatedpage", "no spam in it", "relatedpage");

        // Log in as superadmin
        this.authenticationRule.authenticate();

        // Modify a document with spam to verify that we don't try to remove that modification since it comes from
        // a user having admin rights + verify that the UI shows that the superadmin user won't be removed
        Page page = getUtil().rest().page(getUtil().resolveDocumentReference(getTestClassName() + ".spam-in-content"));
        // We keep the old content (with the spam that the admin user has not seen) + add new content
        page.setContent("new content by admin user\n" + "line1\ngreat hotline\nline2");
        getUtil().rest().save(page, 202);

        // Search for a spam keyword and verify the results
        home = AntiSpamHomePage.gotoPage();
        home = home.searchSpam("hotline");
        // Verify the Matched Pages
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-hotline"));
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-in-title"));
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-xobject"));
        assertTrue(home.getMatchedPagesText().contains("xwiki:AntiSpamTest.spam-in-content"));
        // Verify the Matched Authors
        assertEquals("xwiki:XWiki.spamuser\n"
            + "xwiki:XWiki.superadmin Excluding for safety since it has Admin access to this page",
            home.getMatchedAuthorsText());
        // Verify the Matched Related Pages
        assertEquals("xwiki:XWiki.spamuser\n"
            + "xwiki:AntiSpamTest.spam-in-title\n"
            + "xwiki:AntiSpamTest.spam-hotline\n"
            + "xwiki:AntiSpamTest.spam-xobject\n"
            + "xwiki:AntiSpamTest.relatedpage\n"
            + "xwiki:AntiSpamTest.spam-in-content", home.getMatchedRelatedPagesText());
        // Verify the Matched Activity Stream
        List<String> asTexts = Arrays.asList(StringUtils.split(home.getMatchedActivityStreamText(), "\n "));
        assertTrue(asTexts.size() >= 7);

        // Press "Delete" to clean the spam and press "Confirm Delete"
        home = home.deleteSpam().confirmDeleteSpam();

        // Verify that the Spam pages have been deleted
        assertFalse(getUtil().pageExists("XWiki", "spamuser"));
        assertFalse(getUtil().pageExists(getTestClassName(), "spam-in-title"));
        assertFalse(getUtil().pageExists(getTestClassName(), "spam-hotline"));
        assertFalse(getUtil().pageExists(getTestClassName(), "spam-xobject"));

        // Verify that "spam-in-content" page still exists since a new revision has been created above by the superadmin
        // user but that revision 1.1 is gone.
        assertTrue(getUtil().pageExists(getTestClassName(), "spam-in-content"));
        getUtil().gotoPage(getTestClassName(), "spam-in-content", "viewrev", "rev=1.1");
        vp = new ViewPage();
        assertEquals("", vp.getContent());

        // Click Search again to ensure everything's been deleted
        home = AntiSpamHomePage.gotoPage();
        home = home.searchSpam("hotline");
        assertEquals("xwiki:AntiSpamTest.spam-in-content This change was made by [xwiki:XWiki.superadmin] and won't be "
            + "removed since it's an Admin!", home.getMatchedPagesText());
        assertEquals("xwiki:XWiki.superadmin Excluding for safety since it has Admin access to this page",
            home.getMatchedAuthorsText());
        assertNull(home.getMatchedRelatedPagesText());
        assertNull(home.getMatchedActivityStreamText());
    }

    public void verifyInactiveUserCleaning()
    {
        getUtil().loginAsSuperAdmin();

        // Create a user profile page with a date in the past so that it's considered inactive.
        getUtil().createUser("InactiveUser", "pass", null);
        // Note: the content requires PR so we need to exclude it for the PR checker in the pom.xml
        getUtil().createPage(getTestClassName(), "InactiveUserSetup", "{{velocity}}\n"
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

    /**
     * @todo Once this application depends on XWiki 8.0M1+ remove this method and instead use ViewPage.getErrorContent()
     */
    public String getErrorContent()
    {
        return getDriver().findElementWithoutWaiting(
            By.xpath("//div[@id = 'mainContentArea']/pre[contains(@class, 'xwikierror')]")).getText();
    }

    public String getErrorMessage()
    {
        return getDriver().findElementWithoutWaiting(
            By.xpath("//div[@id = 'mainContentArea']//div[contains(@class, 'panel-body')]/p")).getText();
    }
}
