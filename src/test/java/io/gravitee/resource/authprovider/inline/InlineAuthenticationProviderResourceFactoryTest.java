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
import java.util.Map;
import org.junit.jupiter.api.Test;

class InlineAuthenticationProviderResourceFactoryTest {

    @Test
    void should_resolve_password_expression_when_created_by_resource_factory() throws Exception {
        var deploymentContext = Helper.deploymentContextWithProperties(Map.of("pwd", "secret"));
        InlineAuthenticationProviderResource resource = Helper.resourceFromFactory(
            deploymentContext,
            Helper.user("alice", "{#properties['pwd']}")
        );

        resource.start();

        assertThat(resource.isUsable()).isTrue();
        Authentication authentication = Helper.authenticate(resource, "alice", "secret");
        assertThat(authentication).isNotNull();
        assertThat(authentication.getUsername()).isEqualTo("alice");
    }

    @Test
    void should_refuse_authentication_when_property_is_missing() throws Exception {
        var deploymentContext = Helper.deploymentContextWithProperties(Map.of());
        InlineAuthenticationProviderResource resource = Helper.resourceFromFactory(
            deploymentContext,
            Helper.user("alice", "{#properties['missing']}")
        );

        resource.start();

        assertThat(resource.isUsable()).isFalse();
        assertThat(Helper.authenticate(resource, "alice", "secret")).isNull();
    }

    @Test
    void should_refuse_authentication_when_composite_expression_resolves_to_blank() throws Exception {
        var deploymentContext = Helper.deploymentContextWithProperties(Map.of("left", "", "right", ""));
        InlineAuthenticationProviderResource resource = Helper.resourceFromFactory(
            deploymentContext,
            Helper.user("alice", "{#properties['left']}{#properties['right']}")
        );

        resource.start();

        assertThat(resource.isUsable()).isFalse();
        assertThat(Helper.authenticate(resource, "alice", "")).isNull();
    }
}
