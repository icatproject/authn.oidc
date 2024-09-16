
package org.icatproject.authn_oidc.TestProfiles;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

public class BadScopeTestProfile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "requiredScope", "someOtherScope"
        );
    }
}