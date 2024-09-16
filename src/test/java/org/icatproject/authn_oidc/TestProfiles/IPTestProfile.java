package org.icatproject.authn_oidc.TestProfiles;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

public class IPTestProfile implements QuarkusTestProfile {
	@Override
	public Map<String, String> getConfigOverrides() {
		return Map.of(
				"ip", "130.10.0.1/24 192.168.0.1/24"
		);
	}
}
