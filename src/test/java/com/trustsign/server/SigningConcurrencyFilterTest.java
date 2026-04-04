package com.trustsign.server;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SigningConcurrencyFilterTest {

  @Test
  void requiresSlot_matchesSigningPosts() {
    assertTrue(SigningConcurrencyFilter.requiresSlot("POST", "/sign-pdf"));
    assertTrue(SigningConcurrencyFilter.requiresSlot("POST", "/hsm/sign-pdf"));
    assertTrue(SigningConcurrencyFilter.requiresSlot("GET", "/certificates"));
    assertFalse(SigningConcurrencyFilter.requiresSlot("GET", "/health"));
    assertFalse(SigningConcurrencyFilter.requiresSlot("POST", "/verify-pdf"));
    assertFalse(SigningConcurrencyFilter.requiresSlot("POST", "/session"));
  }
}
