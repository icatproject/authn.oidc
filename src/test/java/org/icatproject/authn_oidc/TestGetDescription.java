package org.icatproject.authn_oidc;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestGetDescription {
	@Test
	public void test() throws Exception {
		OIDC_Authenticator a = new OIDC_Authenticator();
		assertEquals("{\"keys\":[{\"name\":\"token\",\"hide\":true}]}", a.getDescription());

	}
}