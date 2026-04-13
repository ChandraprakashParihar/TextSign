package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.ConfigLoader;
import com.trustsign.core.LicenceEnforcer;
import com.trustsign.core.SessionManager;
import jakarta.servlet.MultipartConfigElement;
import org.apache.coyote.ProtocolHandler;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.lang.NonNull;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.File;
import java.util.Objects;

@Configuration
public class SpringServerConfig {

  @Bean
  public File configFile() {
    String cfgPath = System.getProperty("trustsign.config.path");
    if (cfgPath != null && !cfgPath.isBlank()) {
      return new File(cfgPath);
    }
    return Main.resolveConfigFile(new String[0]);
  }

  @Bean
  public AgentConfig agentConfig(File configFile) throws Exception {
    return ConfigLoader.load(configFile);
  }

  @Bean
  public LicenceEnforcer licenceEnforcer(File configFile) throws Exception {
    return Main.createLicenceEnforcer(configFile);
  }

  @Bean
  public SessionManager sessionManager() {
    return new SessionManager();
  }

  @Bean
  public SigningConcurrencyGate signingConcurrencyGate(AgentConfig cfg) {
    return SigningConcurrencyGate.create(cfg.server());
  }

  @Bean
  public ApiServlet apiServlet(
      SessionManager sessions,
      LicenceEnforcer licenceEnforcer,
      SigningConcurrencyGate signingGate,
      AgentConfig cfg) {
    return new ApiServlet(sessions, licenceEnforcer, signingGate, cfg.server());
  }

  @Bean
  public FilterRegistrationBean<SigningConcurrencyFilter> signingFilterRegistration(
      SigningConcurrencyGate signingGate,
      AgentConfig cfg) {
    FilterRegistrationBean<SigningConcurrencyFilter> bean =
        new FilterRegistrationBean<>(new SigningConcurrencyFilter(signingGate, cfg.server()));
    bean.addUrlPatterns("/v1/*");
    bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
    return bean;
  }

  @Bean
  public MultipartConfigElement multipartConfigElement(AgentConfig cfg) {
    int pdfMb = AgentConfig.ServerConfig.multipartPdfMaxFileMbOrDefault(cfg.server());
    int textMb = AgentConfig.ServerConfig.multipartTextMaxFileMbOrDefault(cfg.server());
    int maxFile = Math.max(pdfMb, textMb) * 1024 * 1024;
    long maxReq = maxFile + (2L * 1024 * 1024);
    return new MultipartConfigElement(
        System.getProperty("java.io.tmpdir"),
        maxFile,
        maxReq,
        512 * 1024);
  }

  @Bean
  public WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatTuningCustomizer(AgentConfig cfg) {
    AgentConfig.ServerConfig serverCfg = cfg.server();
    return factory -> {
      factory.addConnectorCustomizers(connector -> {
        connector.setProperty(
            "maxThreads",
            String.valueOf(AgentConfig.ServerConfig.maxThreadsOrDefault(serverCfg)));
        connector.setProperty(
            "minSpareThreads",
            String.valueOf(AgentConfig.ServerConfig.minSpareThreadsOrDefault(serverCfg)));
        connector.setProperty(
            "acceptCount",
            String.valueOf(AgentConfig.ServerConfig.acceptQueueSizeOrDefault(serverCfg)));
        connector.setProperty(
            "connectionTimeout",
            String.valueOf(AgentConfig.ServerConfig.connectorIdleTimeoutMsOrDefault(serverCfg)));
        int maxConnections = AgentConfig.ServerConfig.maxTcpConnectionsOrDefault(serverCfg);
        if (maxConnections > 0) {
          connector.setProperty("maxConnections", String.valueOf(maxConnections));
        }
        ProtocolHandler handler = connector.getProtocolHandler();
        if (handler instanceof AbstractHttp11Protocol<?> http11) {
          int maxHeaderBytes = AgentConfig.ServerConfig.requestHeaderSizeBytesOrDefault(serverCfg);
          http11.setMaxHttpRequestHeaderSize(maxHeaderBytes);
          http11.setMaxHttpResponseHeaderSize(
              AgentConfig.ServerConfig.responseHeaderSizeBytesOrDefault(serverCfg));
          http11.setKeepAliveTimeout(AgentConfig.ServerConfig.threadIdleTimeoutMsOrDefault(serverCfg));
        }
      });
    };
  }

  @Bean
  public WebMvcConfigurer corsConfigurer(AgentConfig cfg) {
    return new WebMvcConfigurer() {
      @Override
      public void addCorsMappings(@NonNull CorsRegistry registry) {
        if (cfg.allowedOrigins() == null || cfg.allowedOrigins().isEmpty()) {
          return;
        }
        String[] allowedOrigins = Objects.requireNonNull(cfg.allowedOrigins().toArray(new String[0]));
        registry.addMapping("/v1/**")
            .allowedOrigins(allowedOrigins)
            .allowedMethods("GET", "POST", "OPTIONS")
            .allowedHeaders("*");
      }
    };
  }
}

