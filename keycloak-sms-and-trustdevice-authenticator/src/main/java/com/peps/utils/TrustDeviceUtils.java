package com.peps.utils;

import eu.bitwalker.useragentutils.UserAgent;
import com.peps.authenticator.TrustDeviceAuthenticatorFactory;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.services.util.CookieHelper;

import javax.ws.rs.core.Cookie;
import java.net.URI;
import java.time.Instant;
import java.util.Base64;

import java.util.UUID;

public class TrustDeviceUtils {

    public static final String COOKIE_NAME = "DEVICE-ID";
    public static final int DURATION_DAYS = 30;

    public static  String getUserAgent(AuthenticationFlowContext context) {
        return context.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst("User-Agent");
    }

    public static  String generateRememberMeCookie(AuthenticationFlowContext context) {
        UserAgent userAgent = UserAgent.parseUserAgentString(getUserAgent(context));
        String useragentString = userAgent.toString();
        String uuid = context.getUser().getFirstAttribute(useragentString);
        if(uuid == null) {
            uuid = UUID.randomUUID().toString();
        }
        else if(uuid.contains("##")){
            uuid = uuid.substring(0,uuid.lastIndexOf("##"));
        }

        StringBuilder uuidTimestamp = new StringBuilder();
        uuidTimestamp.append(uuid);
        uuidTimestamp.append("##");
        uuidTimestamp.append(System.currentTimeMillis());
        context.getUser().setSingleAttribute(useragentString, uuidTimestamp.toString());
        StringBuilder cookie = new StringBuilder();
        cookie.append(uuid);
        cookie.append(".");
        cookie.append(useragentString);
        return Base64.getEncoder().encodeToString(cookie.toString().getBytes());
    }

    public static  String getCookie(AuthenticationFlowContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(COOKIE_NAME);
        if(cookie != null) {
            return cookie.getValue();
        }
        return null;
    }

    public static  boolean isValidRememberMeCookie(AuthenticationFlowContext context) {
        String duration = "0";
        if(context.getAuthenticatorConfig() != null) {
            duration = context.getAuthenticatorConfig().getConfig().get(TrustDeviceAuthenticatorFactory.PARAMETER_MAX_LIFESPAN);
        }
        if(duration == null) {
            duration = "0";
        }
        String cookie = getCookie(context);
        if (cookie == null) {
            return false;
        }

        try {
            UserAgent userAgent = UserAgent.parseUserAgentString(getUserAgent(context));
            String userAgentString = userAgent.toString();
            String uuidTimestamp = context.getUser().getFirstAttribute(userAgentString);
            String decodedCookie =  new String(Base64.getDecoder().decode(cookie));
            String[] splittedCookie = decodedCookie.split("\\.");
            String[] splittedId = uuidTimestamp.split("##");

            String uuid = splittedId[0];
            String lastAccess = splittedId[1];

            String uuidstored = splittedCookie[0];
            String useragentCookie = splittedCookie[1];

            if(Instant.ofEpochMilli(Long.parseLong(lastAccess)).plusSeconds(60*Integer.parseInt(duration)).isBefore(Instant.now())) {
                return false;
            }
            if(!uuidstored.equals(uuid)){
                return false;
            }
            if(!useragentCookie.equals(userAgentString)){
                return false;
            }
        }
        catch (Exception e) {
            return false;
        }
        return true;
    }

    public static void setCookie(AuthenticationFlowContext context, String cookie) {

        int maxCookieAge = 60 * 60 * 24 * DURATION_DAYS; // 30 days
        URI uri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();

        CookieHelper.addCookie(COOKIE_NAME, cookie,
                uri.getRawPath(),
                null, null,
                maxCookieAge,
                false, true);
    }
}
