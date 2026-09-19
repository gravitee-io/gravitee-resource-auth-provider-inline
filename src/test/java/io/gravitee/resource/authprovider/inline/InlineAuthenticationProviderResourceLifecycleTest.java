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

import org.junit.jupiter.api.Test;

class InlineAuthenticationProviderResourceLifecycleTest {

    @Test
    void should_keep_literal_passwords_usable_without_deployment_context() throws Exception {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "MyP@ssw0rd!"));

        resource.start();

        assertThat(resource.isUsable()).isTrue();
        assertThat(Helper.authenticate(resource, "alice", "MyP@ssw0rd!")).isNotNull();
    }

    @Test
    void should_refuse_authentication_when_legacy_classloader_and_password_has_el_marker() throws Exception {
        InlineAuthenticationProviderResource resource = Helper.resourceWithUsers(Helper.user("alice", "{#properties['password']}"));

        resource.start();

        assertThat(resource.isUsable()).isFalse();
        assertThat(Helper.authenticate(resource, "alice", "secret")).isNull();
    }
}
