/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.peps.authenticator;



import com.peps.utils.TrustDeviceUtils;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.validation.Validation;
import org.keycloak.utils.CredentialHelper;

import javax.ws.rs.core.MultivaluedMap;


public class SMSOTPAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {
    protected static ServicesLogger log = ServicesLogger.LOGGER;


    @Override
    public void authenticate(AuthenticationFlowContext context) {

        //SEND SMS CHALLENGE
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {

            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            Boolean rememberDevice = formData.getFirst("rememberDevice") != null && formData.getFirst("rememberDevice").equals("on");
            if(rememberDevice) {
                String cookie = TrustDeviceUtils.generateRememberMeCookie(context);
                TrustDeviceUtils.setCookie(context, cookie);
            }
            context.success();
        }


    @Override
    public boolean requiresUser() {
        return true;
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {

    }
}
