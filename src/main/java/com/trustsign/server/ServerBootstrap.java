package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.LicenceEnforcer;
import com.trustsign.core.SessionManager;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.MultipartConfigElement;
import org.eclipse.jetty.server.ConnectionLimit;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import java.util.EnumSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ServerBootstrap {

  private static final Logger LOG = LoggerFactory.getLogger(ServerBootstrap.class);

  public static Server buildServer(AgentConfig cfg, LicenceEnforcer licenceEnforcer) {
    AgentConfig.ServerConfig sc = cfg.server();
    SessionManager sessions = new SessionManager();

    QueuedThreadPool pool = new QueuedThreadPool();
    pool.setName("trustsign-http");
    pool.setMaxThreads(AgentConfig.ServerConfig.jettyMaxThreadsOrDefault(sc));
    pool.setMinThreads(AgentConfig.ServerConfig.jettyMinThreadsOrDefault(sc));
    pool.setIdleTimeout(AgentConfig.ServerConfig.jettyThreadIdleTimeoutMsOrDefault(sc));

    Server server = new Server(pool);

    int maxTcp = AgentConfig.ServerConfig.maxTcpConnectionsOrDefault(sc);
    if (maxTcp > 0) {
      server.addBean(new ConnectionLimit(maxTcp, server));
    }

    HttpConfiguration httpConfig = new HttpConfiguration();
    httpConfig.setRequestHeaderSize(AgentConfig.ServerConfig.requestHeaderSizeBytesOrDefault(sc));
    httpConfig.setResponseHeaderSize(AgentConfig.ServerConfig.responseHeaderSizeBytesOrDefault(sc));
    HttpConnectionFactory httpFactory = new HttpConnectionFactory(httpConfig);

    ServerConnector connector = new ServerConnector(server, httpFactory);
    connector.setHost("0.0.0.0");
    connector.setPort(cfg.portOrDefault());
    connector.setIdleTimeout(AgentConfig.ServerConfig.connectorIdleTimeoutMsOrDefault(sc));
    connector.setAcceptQueueSize(AgentConfig.ServerConfig.acceptQueueSizeOrDefault(sc));
    server.addConnector(connector);

    SigningConcurrencyGate signingGate = SigningConcurrencyGate.create(sc);

    ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
    ctx.setContextPath("/");

    FilterHolder signFilter = new FilterHolder(new SigningConcurrencyFilter(signingGate, sc));
    ctx.addFilter(signFilter, "/v1/*", EnumSet.of(DispatcherType.REQUEST));

    ServletHolder api = new ServletHolder(new ApiServlet(sessions, licenceEnforcer, signingGate, sc));

    int pdfMb = AgentConfig.ServerConfig.multipartPdfMaxFileMbOrDefault(sc);
    int textMb = AgentConfig.ServerConfig.multipartTextMaxFileMbOrDefault(sc);
    int maxFile = Math.max(pdfMb, textMb) * 1024 * 1024;
    long maxReq = maxFile + (2L * 1024 * 1024);

    api.getRegistration().setMultipartConfig(new MultipartConfigElement(
        System.getProperty("java.io.tmpdir"),
        maxFile,
        maxReq,
        512 * 1024
    ));

    ctx.addServlet(api, "/v1/*");

    server.setHandler(ctx);

    int signMax = AgentConfig.ServerConfig.maxConcurrentSigningOrDefault(sc);
    LOG.info("TrustSign listener: port={} jettyMaxThreads={} acceptQueue={} signingConcurrency={} tcpConnectionCap={}",
        cfg.portOrDefault(),
        pool.getMaxThreads(),
        connector.getAcceptQueueSize(),
        signMax <= 0 ? "unlimited" : String.valueOf(signMax),
        maxTcp <= 0 ? "none" : String.valueOf(maxTcp));

    return server;
  }

  private ServerBootstrap() {}
}
