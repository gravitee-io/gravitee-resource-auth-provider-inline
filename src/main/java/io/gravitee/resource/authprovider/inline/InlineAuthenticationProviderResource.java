/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.resource.authprovider.inline;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.reactive.api.context.DeploymentContext;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import io.gravitee.resource.authprovider.inline.configuration.InlineAuthenticationProviderResourceConfiguration;
import io.gravitee.resource.authprovider.inline.configuration.InlineAuthenticationProviderResourceConfigurationEvaluator;
import io.gravitee.resource.authprovider.inline.model.User;
import java.util.List;
import java.util.Optional;
import javax.inject.Inject;
import lombok.CustomLog;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@CustomLog
public class InlineAuthenticationProviderResource
    extends AuthenticationProviderResource<InlineAuthenticationProviderResourceConfiguration> {

    @Inject
    private DeploymentContext deploymentContext;

    private InlineAuthenticationProviderResourceConfiguration evaluatedConfiguration;
    private boolean usable = true;
    private String unusableReason;

    @Override
    public InlineAuthenticationProviderResourceConfiguration configuration() {
        if (evaluatedConfiguration != null) {
            return evaluatedConfiguration;
        }
        return super.configuration();
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        InlineAuthenticationProviderResourceConfiguration rawConfiguration = super.configuration();

        if (deploymentContext == null) {
            if (ConfigurationPasswords.containsElMarker(rawConfiguration)) {
                markUnusable(
                    "Legacy resource classloader cannot evaluate EL expressions in inline user passwords; authentication is disabled",
                    null
                );
                return;
            }
            evaluatedConfiguration = rawConfiguration;
            return;
        }

        try {
            InlineAuthenticationProviderResourceConfiguration evaluated = new InlineAuthenticationProviderResourceConfigurationEvaluator(
                rawConfiguration
            ).evalNow(deploymentContext);
            ConfigurationPasswords.validateResolvedPasswords(rawConfiguration, evaluated);
            evaluatedConfiguration = evaluated;
        } catch (Exception exception) {
            markUnusable("Unable to evaluate inline authentication provider configuration", exception);
        }
    }

    @Override
    public void authenticate(String username, String password, ExecutionContext executionContext, Handler<Authentication> handler) {
        if (!usable) {
            log.warn("Refusing inline authentication: {}", unusableReason);
            handler.handle(null);
            return;
        }

        List<User> users = configuration().getUsers();
        if (users == null) {
            handler.handle(null);
            return;
        }

        Optional<User> userMatch = users
            .stream()
            .filter(user -> user.getUsername().equalsIgnoreCase(username))
            .findFirst();

        if (userMatch.isEmpty()) {
            handler.handle(null);
            return;
        }

        Authentication authentication = null;

        if (password == null || password.equals(userMatch.get().getPassword())) {
            authentication = new Authentication(username);
        }

        handler.handle(authentication);
    }

    boolean isUsable() {
        return usable;
    }

    String unusableReason() {
        return unusableReason;
    }

    private void markUnusable(String reason, Throwable cause) {
        usable = false;
        unusableReason = reason;
        if (cause == null) {
            log.error(reason);
        } else {
            log.error(reason, cause);
        }
    }
}
