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

import io.gravitee.resource.authprovider.inline.configuration.InlineAuthenticationProviderResourceConfiguration;
import io.gravitee.resource.authprovider.inline.model.User;
import java.util.List;
import java.util.regex.Pattern;

final class ConfigurationPasswords {

    private static final Pattern EL_MARKER = Pattern.compile("\\{ *([#T(])((?>[^{}]+|\\{(?>[^{}]+)*\\})*\\})");

    private ConfigurationPasswords() {}

    static boolean containsElMarker(String value) {
        return value != null && EL_MARKER.matcher(value).find();
    }

    static boolean containsElMarker(InlineAuthenticationProviderResourceConfiguration configuration) {
        if (configuration == null || configuration.getUsers() == null) {
            return false;
        }
        return configuration
            .getUsers()
            .stream()
            .anyMatch(user -> containsElMarker(user.getPassword()));
    }

    static void validateResolvedPasswords(
        InlineAuthenticationProviderResourceConfiguration raw,
        InlineAuthenticationProviderResourceConfiguration evaluated
    ) {
        if (raw.getUsers() == null) {
            return;
        }

        List<User> evaluatedUsers = evaluated.getUsers();
        if (evaluatedUsers == null || evaluatedUsers.size() != raw.getUsers().size()) {
            throw new IllegalStateException("Evaluated inline user configuration is incomplete");
        }

        for (int index = 0; index < raw.getUsers().size(); index++) {
            User rawUser = raw.getUsers().get(index);
            String rawPassword = rawUser.getPassword();
            if (!containsElMarker(rawPassword)) {
                continue;
            }

            String resolvedPassword = evaluatedUsers.get(index).getPassword();
            if (resolvedPassword == null || resolvedPassword.isBlank() || rawPassword.equals(resolvedPassword)) {
                throw new IllegalStateException(
                    "Password expression for user '" + rawUser.getUsername() + "' did not resolve to a usable value"
                );
            }
        }
    }
}
