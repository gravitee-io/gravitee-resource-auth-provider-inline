/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
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
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import io.gravitee.resource.authprovider.inline.configuration.InlineAuthenticationProviderResourceConfiguration;
import io.gravitee.resource.authprovider.inline.model.User;
import java.util.Optional;
import java.util.Set;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class InlineAuthenticationProviderResource
    extends AuthenticationProviderResource<InlineAuthenticationProviderResourceConfiguration> {

    @Override
    public void authenticate(String username, String password, ExecutionContext executionContext, Handler<Authentication> handler) {
        Set<User> users = configuration().getUsers();
        if (users == null) {
            handler.handle(null);
            return;
        }

        Optional<User> userMatch = configuration()
            .getUsers()
            .stream()
            .filter(user -> user.getUsername().equalsIgnoreCase(username))
            .findFirst();

        // No user match the username
        if (!userMatch.isPresent()) {
            handler.handle(null);
            return;
        }

        Authentication authentication = null;

        if (password == null || password.equals(userMatch.get().getPassword())) {
            authentication = new Authentication(username);
        }

        handler.handle(authentication);
    }
}
