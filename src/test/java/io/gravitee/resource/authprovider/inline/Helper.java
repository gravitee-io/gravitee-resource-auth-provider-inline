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

import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.authprovider.inline.configuration.InlineAuthenticationProviderResourceConfiguration;
import io.gravitee.resource.authprovider.inline.model.User;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

final class Helper {

    private Helper() {}

    static InlineAuthenticationProviderResource resourceWithUsers(User... users) {
        InlineAuthenticationProviderResourceConfiguration configuration = new InlineAuthenticationProviderResourceConfiguration();
        configuration.setUsers(users.length == 0 ? null : new LinkedHashSet<>(Arrays.asList(users)));

        InlineAuthenticationProviderResource resource = new InlineAuthenticationProviderResource();
        setConfiguration(resource, configuration);
        return resource;
    }

    static User user(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        return user;
    }

    private static void setConfiguration(
        InlineAuthenticationProviderResource resource,
        InlineAuthenticationProviderResourceConfiguration configuration
    ) {
        try {
            Field field = AbstractConfigurableResource.class.getDeclaredField("configuration");
            field.setAccessible(true);
            field.set(resource, configuration);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unable to inject resource configuration for tests", e);
        }
    }
}
