package org.icatproject.authn_oidc.TestProfiles;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

    public class WellKnownTestProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "wellKnownUrl", "http://localhost:5050/realms/wrong/.well-known/openid-configuration"
            );
        }
}
