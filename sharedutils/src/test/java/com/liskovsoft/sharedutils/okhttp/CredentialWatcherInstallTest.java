package com.liskovsoft.sharedutils.okhttp;

import com.liskovsoft.sharedutils.okhttp.interceptors.CredentialWatcher;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

import okhttp3.Interceptor;
import okhttp3.OkHttpClient;

import static org.junit.Assert.assertEquals;

/** Contract revision 10 §6b (e): the watcher is on the shared base client, once, and survives newBuilder(). */
@RunWith(RobolectricTestRunner.class)
public class CredentialWatcherInstallTest {
    @Test
    public void installedOnceOnTheSharedBaseAndKeptByDerivedClients() {
        OkHttpClient base = OkHttpCommons.setupBuilder(new OkHttpClient.Builder()).build();
        assertEquals(1, count(base));
        OkHttpClient derived = CredentialWatcher.install(base.newBuilder()).build();
        assertEquals(1, count(derived));
        assertEquals(1, count(CredentialWatcher.install(new OkHttpClient.Builder()).build()));
    }

    private static int count(OkHttpClient client) {
        int n = 0;
        for (Interceptor i : client.networkInterceptors()) {
            if (i == CredentialWatcher.INSTANCE) n++;
        }
        return n;
    }
}
