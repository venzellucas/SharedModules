package com.liskovsoft.sharedutils.okhttp.interceptors;

import android.util.Log;

import androidx.annotation.Nullable;

import com.liskovsoft.sharedutils.okhttp.AccountRouteTag;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * UltimateTube(cookie-auth), contract revision 10 §6b: the credential watcher of the debug-only
 * measurement build. A NETWORK interceptor on every OkHttp client of the app and the engine
 * that logs one line for each request leaving with a YouTube credential - a session cookie, a
 * SAPISIDHASH or an OAuth bearer - with its host and path and whether that request is an
 * account route. It measures criterion (e): the interceptor that adds the session only sees
 * what it did itself.
 *
 * <p>The line carries host, path (never the query) and the credential KINDS. Header values,
 * cookie names-with-values and query strings never reach the log. Off unless the app enables
 * it, which only a debug build with debug.arc.cookie_auth=1 does; disabled, it only forwards.
 */
public final class CredentialWatcher implements Interceptor {
    public static final CredentialWatcher INSTANCE = new CredentialWatcher();
    public static final String TAG = "CredWatch";

    /** Where lines go; a seam for tests. */
    public interface Sink {
        void log(String line);
    }

    private static final Sink LOGCAT = line -> Log.i(TAG, line);
    private static final Set<String> SESSION_COOKIES = new HashSet<>(Arrays.asList(
            "SID", "HSID", "SSID", "APISID", "SAPISID", "SIDCC", "LOGIN_INFO"));
    private static final Set<String> ACCOUNT_HOSTS = new HashSet<>(Arrays.asList(
            "www.youtube.com", "m.youtube.com", "music.youtube.com"));

    private static volatile boolean sEnabled;
    private static volatile Sink sSink = LOGCAT;

    private CredentialWatcher() {
    }

    public static void setEnabled(boolean enabled) {
        sEnabled = enabled;
    }

    public static boolean isEnabled() {
        return sEnabled;
    }

    /** Tests only: null restores logcat. */
    public static void setSink(@Nullable Sink sink) {
        sSink = sink != null ? sink : LOGCAT;
    }

    /** Adds the watcher once; a builder derived with newBuilder() already carries it. */
    public static OkHttpClient.Builder install(OkHttpClient.Builder builder) {
        if (!builder.networkInterceptors().contains(INSTANCE)) {
            builder.addNetworkInterceptor(INSTANCE);
        }
        return builder;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        observe(request);
        return chain.proceed(request);
    }

    /** Logs the request's line when enabled and it carries a credential. */
    static void observe(Request request) {
        if (sEnabled) {
            String line = describe(request);
            if (line != null) {
                sSink.log(line);
            }
        }
    }

    /** The log line for a request, or null when it carries no YouTube credential. */
    @Nullable
    public static String describe(Request request) {
        String host = request.url().host();
        String path = request.url().encodedPath();
        StringBuilder kinds = new StringBuilder();
        if (hasSessionCookie(request.headers("Cookie"))) {
            kinds.append("cookie");
        }
        for (String auth : request.headers("Authorization")) {
            String scheme = auth.trim();
            int space = scheme.indexOf(' ');
            scheme = (space > 0 ? scheme.substring(0, space) : scheme).toUpperCase(java.util.Locale.ROOT);
            if (scheme.startsWith("SAPISID") && scheme.endsWith("HASH")) {
                append(kinds, "sapisidhash");
            } else if (scheme.equals("BEARER") && !isDriveRequest(host, path)) {
                // The Drive backup token belongs on the Drive hosts and is not counted there.
                append(kinds, "oauth");
            }
        }
        if (kinds.length() == 0) {
            return null;
        }
        return "cred " + (isAccountRoute(request) ? "account" : "LEAK") + " kinds=" + kinds
                + " host=" + host + " path=" + path;
    }

    /**
     * §6b account routes: InnerTube on the YouTube hosts, never the PO-token /att/get or
     * visitor_id, and a /player only when its route carries the account (the tag).
     */
    public static boolean isAccountRoute(Request request) {
        String path = request.url().encodedPath();
        if (!request.url().isHttps() || !ACCOUNT_HOSTS.contains(request.url().host())
                || !path.startsWith("/youtubei/v1/")
                || path.endsWith("/att/get") || path.endsWith("/visitor_id")) {
            return false;
        }
        return !path.equals("/youtubei/v1/player") || request.tag(AccountRouteTag.class) != null;
    }

    static boolean hasSessionCookie(List<String> cookieHeaders) {
        for (String header : cookieHeaders) {
            for (String part : header.split(";")) {
                int eq = part.indexOf('=');
                String name = (eq >= 0 ? part.substring(0, eq) : part).trim();
                if (SESSION_COOKIES.contains(name) || (name.startsWith("__Secure-")
                        && (name.contains("PSID") || name.contains("APISID")))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isDriveRequest(String host, String path) {
        return "www.googleapis.com".equals(host)
                && (path.startsWith("/drive/v3") || path.startsWith("/upload/drive/v3"));
    }

    private static void append(StringBuilder kinds, String kind) {
        if (kinds.indexOf(kind) < 0) {
            kinds.append(kinds.length() == 0 ? "" : "+").append(kind);
        }
    }
}
