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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ConfigurationPasswordsTest {

    @Test
    void should_detect_el_marker_in_secret_expression() {
        assertThat(ConfigurationPasswords.containsElMarker("{#secrets.get('/vault/pwd')}")).isTrue();
    }

    @Test
    void should_not_detect_el_marker_in_password_with_braces_only() {
        assertThat(ConfigurationPasswords.containsElMarker("p@ss{word}")).isFalse();
    }

    @Test
    void should_reject_unresolved_password_expression() {
        var raw = Helper.configurationWithUsers(Helper.user("alice", "{#properties['missing']}"));
        var evaluated = Helper.configurationWithUsers(Helper.user("alice", "{#properties['missing']}"));

        assertThatThrownBy(() -> ConfigurationPasswords.validateResolvedPasswords(raw, evaluated))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("did not resolve");
    }

    @Test
    void should_accept_resolved_password_expression() {
        var raw = Helper.configurationWithUsers(Helper.user("alice", "{#properties['password']}"));
        var evaluated = Helper.configurationWithUsers(Helper.user("alice", "secret"));

        ConfigurationPasswords.validateResolvedPasswords(raw, evaluated);
    }
}
