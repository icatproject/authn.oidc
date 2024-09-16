
package org.icatproject.authn_oidc.TestProfiles;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

public class PrependTestProfile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "mechanism", "oidc",
                "icatUserPrependMechanism", "true"
        );
    }
}