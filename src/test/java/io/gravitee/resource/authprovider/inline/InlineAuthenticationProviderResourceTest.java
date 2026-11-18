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

import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.inline.configuration.InlineAuthenticationProviderResourceConfiguration;
import io.gravitee.resource.authprovider.inline.model.User;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.LinkedHashSet;
import org.junit.jupiter.api.Test;

class InlineAuthenticationProviderResourceTest {

    @Test
    void should_authenticate_when_credentials_match() {
        InlineAuthenticationProviderResource resource = resourceWithUsers(user("alice", "MyP@ssw0rd!"));

        Authentication authentication = authenticate(resource, "alice", "MyP@ssw0rd!");

        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("alice");
    }

    @Test
    void should_authenticate_when_username_matches_case_insensitively() {
        InlineAuthenticationProviderResource resource = resourceWithUsers(user("alice", "secret"));

        Authentication authentication = authenticate(resource, "ALICE", "secret");

        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("ALICE");
    }

    @Test
    void should_reject_unknown_user() {
        InlineAuthenticationProviderResource resource = resourceWithUsers(user("alice", "secret"));

        assertThat(authenticate(resource, "bob", "secret")).isNull();
    }

    @Test
    void should_reject_wrong_password() {
        InlineAuthenticationProviderResource resource = resourceWithUsers(user("alice", "secret"));

        assertThat(authenticate(resource, "alice", "wrong")).isNull();
    }

    @Test
    void should_reject_when_password_is_missing() {
        InlineAuthenticationProviderResource resource = resourceWithUsers(user("alice", "secret"));

        assertThat(authenticate(resource, "alice", null)).isNull();
        assertThat(authenticate(resource, "ALICE", null)).isNull();
    }

    @Test
    void should_reject_user_configured_without_password() {
        InlineAuthenticationProviderResource resource = resourceWithUsers(user("bob", null));

        assertThat(authenticate(resource, "bob", null)).isNull();
    }

    @Test
    void should_reject_when_no_users_configured() {
        InlineAuthenticationProviderResource resource = resourceWithUsers();

        assertThat(authenticate(resource, "alice", "secret")).isNull();
    }

    private static InlineAuthenticationProviderResource resourceWithUsers(User... users) {
        InlineAuthenticationProviderResourceConfiguration configuration = new InlineAuthenticationProviderResourceConfiguration();
        configuration.setUsers(users.length == 0 ? null : new LinkedHashSet<>(Arrays.asList(users)));

        InlineAuthenticationProviderResource resource = new InlineAuthenticationProviderResource();
        try {
            Field field = AbstractConfigurableResource.class.getDeclaredField("configuration");
            field.setAccessible(true);
            field.set(resource, configuration);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Unable to inject resource configuration for tests", e);
        }
        return resource;
    }

    private static User user(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        return user;
    }

    private static Authentication authenticate(InlineAuthenticationProviderResource resource, String username, String password) {
        Authentication[] result = new Authentication[1];
        resource.authenticate(username, password, null, auth -> result[0] = auth);
        return result[0];
    }
}
