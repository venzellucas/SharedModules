package com.liskovsoft.sharedutils.okhttp.interceptors;

import com.liskovsoft.sharedutils.okhttp.AccountRouteTag;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import java.util.ArrayList;
import java.util.List;

import okhttp3.Request;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** Contract revision 10 §6b (e): the measurement build's credential watcher. */
@RunWith(RobolectricTestRunner.class)
public class CredentialWatcherTest {
    private static final String SAPISID = "sEcReTsApIsId123/AbC";
    private static final String COOKIE = "YSC=abc; SAPISID=" + SAPISID + "; __Secure-3PAPISID=" + SAPISID
            + "; SID=sidValue987; LOGIN_INFO=loginValue555";
    private static final String HASH = "SAPISIDHASH 1759000000_0123456789abcdef0123456789abcdef01234567";

    @After
    public void tearDown() {
        CredentialWatcher.setEnabled(false);
        CredentialWatcher.setSink(null);
    }

    @Test
    public void accountBrowseIsAccount_andTheLineHasNoValues() {
        String line = CredentialWatcher.describe(new Request.Builder()
                .url("https://www.youtube.com/youtubei/v1/browse?key=queryKey123&prettyPrint=false")
                .header("Cookie", COOKIE).header("Authorization", HASH).build());
        assertEquals("cred account kinds=cookie+sapisidhash host=www.youtube.com path=/youtubei/v1/browse", line);
        assertNoSecrets(line);
    }

    @Test
    public void playerWithoutTheAccountTagIsALeak_withTheTagAnAccountRoute() {
        Request.Builder player = new Request.Builder().url("https://www.youtube.com/youtubei/v1/player")
                .header("Cookie", COOKIE);
        assertTrue(CredentialWatcher.describe(player.build()).startsWith("cred LEAK kinds=cookie "));
        player.tag(AccountRouteTag.class, AccountRouteTag.INSTANCE);
        assertTrue(CredentialWatcher.describe(player.build()).startsWith("cred account "));
    }

    @Test
    public void poTokenAndVisitorRoutesAndOtherHostsAreLeaks() {
        String[] urls = {
                "https://www.youtube.com/youtubei/v1/att/get?prettyPrint=false",
                "https://www.youtube.com/youtubei/v1/visitor_id",
                "https://www.youtube.com/watch?v=abc",
                "https://youtubei.googleapis.com/youtubei/v1/browse",
                "https://rr1---sn-abc.googlevideo.com/videoplayback",
                "https://www.youtube.com/api/stats/watchtime",
                "http://www.youtube.com/youtubei/v1/browse",
        };
        for (String url : urls) {
            String line = CredentialWatcher.describe(new Request.Builder().url(url).header("Authorization", HASH).build());
            assertTrue(url, line.startsWith("cred LEAK kinds=sapisidhash "));
        }
    }

    @Test
    public void consentAndVisitorCookiesAreNotCredentials() {
        assertNull(CredentialWatcher.describe(new Request.Builder()
                .url("https://www.youtube.com/youtubei/v1/visitor_id").header("Cookie", "SOCS=CAE=").build()));
        assertNull(CredentialWatcher.describe(new Request.Builder()
                .url("https://www.youtube.com/").header("Cookie", "SOCS=CAI; VISITOR_INFO1_LIVE=x; YSC=y").build()));
    }

    @Test
    public void driveTokenCountsOnlyOutsideTheDriveHosts() {
        assertNull(CredentialWatcher.describe(new Request.Builder()
                .url("https://www.googleapis.com/drive/v3/files").header("Authorization", "Bearer ya29.drive").build()));
        assertNull(CredentialWatcher.describe(new Request.Builder()
                .url("https://www.googleapis.com/upload/drive/v3/files").header("Authorization", "Bearer ya29.drive").build()));
        String line = CredentialWatcher.describe(new Request.Builder()
                .url("https://www.googleapis.com/oauth2/v4/token").header("Authorization", "Bearer ya29.secretToken").build());
        assertEquals("cred LEAK kinds=oauth host=www.googleapis.com path=/oauth2/v4/token", line);
    }

    @Test
    public void secureSessionCookiesAloneCount() {
        assertTrue(CredentialWatcher.hasSessionCookie(java.util.Collections.singletonList("__Secure-1PSID=v")));
        assertTrue(CredentialWatcher.hasSessionCookie(java.util.Collections.singletonList("a=b; __Secure-3PAPISID=v")));
        assertFalse(CredentialWatcher.hasSessionCookie(java.util.Collections.singletonList("__Secure-ROLLOUT_TOKEN=v")));
    }

    @Test
    public void disabledWatcherLogsNothing_enabledLogsOnlyTheSafeLine() {
        List<String> lines = new ArrayList<>();
        CredentialWatcher.setSink(lines::add);
        Request request = new Request.Builder().url("https://music.youtube.com/youtubei/v1/browse?ctoken=tok")
                .header("Cookie", COOKIE).header("Authorization", HASH).build();
        CredentialWatcher.observe(request);
        assertTrue(lines.isEmpty());
        CredentialWatcher.setEnabled(true);
        CredentialWatcher.observe(request);
        assertEquals(1, lines.size());
        assertNoSecrets(lines.get(0));
        assertFalse(lines.get(0).contains("tok"));
    }

    private static void assertNoSecrets(String line) {
        for (String secret : new String[] {SAPISID, "sidValue987", "loginValue555", "0123456789abcdef",
                "queryKey123", "SAPISID=", "Bearer"}) {
            assertFalse(line + " contains " + secret, line.contains(secret));
        }
    }
}
