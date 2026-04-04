package com.trustsign.hsm;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HsmPkcs11ConfigurationServiceTest {

  @Test
  void normalizeSlotProbeCount_defaultsWhenNonPositive() {
    assertEquals(32, HsmPkcs11ConfigurationService.normalizeSlotProbeCount(0));
    assertEquals(32, HsmPkcs11ConfigurationService.normalizeSlotProbeCount(-1));
  }

  @Test
  void normalizeSlotProbeCount_capsAtMax() {
    assertEquals(256, HsmPkcs11ConfigurationService.normalizeSlotProbeCount(500));
    assertEquals(64, HsmPkcs11ConfigurationService.normalizeSlotProbeCount(64));
  }
}
