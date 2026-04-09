package com.trustsign.server;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.LicenceEnforcer;
import com.trustsign.core.SessionManager;
import java.io.File;
import jakarta.servlet.MultipartConfigElement;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

class SpringServerConfigTest {

  @Test
  void createsApiBeanFilterAndMultipartConfig() throws Exception {
    SpringServerConfig cfg = new SpringServerConfig();
    File configFile = Main.resolveConfigFile(new String[0]);
    AgentConfig ac = ConfigLoader.load(configFile);
    SessionManager sm = new SessionManager();
    SigningConcurrencyGate gate = SigningConcurrencyGate.create(ac.server());
    LicenceEnforcer le = null;

    ApiServlet servlet = cfg.apiServlet(sm, le, gate, ac);
    FilterRegistrationBean<SigningConcurrencyFilter> filter = cfg.signingFilterRegistration(gate, ac);
    MultipartConfigElement multipart = cfg.multipartConfigElement(ac);

    assertNotNull(servlet);
    assertNotNull(filter);
    assertNotNull(multipart);
  }
}

