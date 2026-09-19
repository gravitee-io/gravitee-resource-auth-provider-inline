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

import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.resource.authprovider.api.Authentication;
import org.junit.jupiter.api.Test;

class InlineAuthenticationProviderResourceTest {

    @Test
    void should_authenticate_when_credentials_match() {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "MyP@ssw0rd!"));

        Authentication authentication = Helper.authenticate(resource, "alice", "MyP@ssw0rd!");

        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("alice");
    }

    @Test
    void should_authenticate_when_username_matches_case_insensitively() {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "secret"));

        Authentication authentication = Helper.authenticate(resource, "ALICE", "secret");

        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("ALICE");
    }

    @Test
    void should_reject_unknown_user() {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "secret"));

        Authentication authentication = Helper.authenticate(resource, "bob", "secret");

        assertThat(authentication).isNull();
    }

    @Test
    void should_reject_wrong_password() {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "secret"));

        Authentication authentication = Helper.authenticate(resource, "alice", "wrong");

        assertThat(authentication).isNull();
    }

    @Test
    void should_reject_when_no_users_configured() {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers();

        Authentication authentication = Helper.authenticate(resource, "alice", "secret");

        assertThat(authentication).isNull();
    }

    @Test
    void should_compare_password_as_literal_string() {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "{#secrets.get('/vault/pwd')}"));

        Authentication authentication = Helper.authenticate(resource, "alice", "{#secrets.get('/vault/pwd')}");

        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("alice");
    }

    @Test
    void should_authenticate_when_password_contains_braces_without_el_marker() {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "p@ss{word}"));

        Authentication authentication = Helper.authenticate(resource, "alice", "p@ss{word}");

        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("alice");
    }
}
