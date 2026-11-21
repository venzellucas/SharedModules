package com.liskovsoft.sharedutils.okhttp;

/**
 * UltimateTube(cookie-auth): OkHttp request tag meaning "this request's route carries the
 * account" (a /player whose planner route has isAuth()). Set by the engine's API interceptor,
 * read by the cookie-auth measurement interceptor and by {@code CredentialWatcher}.
 * Only the debug-only measurement build (debug.arc.cookie_auth) acts on it.
 */
public enum AccountRouteTag {
    INSTANCE
}
