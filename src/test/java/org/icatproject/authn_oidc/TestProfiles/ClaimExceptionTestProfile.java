package org.icatproject.authn_oidc.TestProfiles;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

public class ClaimExceptionTestProfile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "icatUserClaim", "incorrectUser",
                "icatUserClaimException", "true"
        );
    }
}
