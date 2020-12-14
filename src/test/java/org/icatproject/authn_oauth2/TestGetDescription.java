package org.icatproject.authn_oauth2;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestGetDescription {
	@Test
	public void test() throws Exception {
		OAUTH2_Authenticator a = new OAUTH2_Authenticator();
		assertEquals("{\"keys\":[{\"name\":\"token\",\"hide\":true}]}", a.getDescription());

	}
}