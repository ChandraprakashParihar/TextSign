package com.trustsign.server;

import com.trustsign.core.AgentConfig;
import com.trustsign.core.SessionManager;
import jakarta.servlet.MultipartConfigElement;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

public final class ServerBootstrap {

  public static Server buildServer(AgentConfig cfg) {
    SessionManager sessions = new SessionManager();

    Server server = new Server();

    ServerConnector connector = new ServerConnector(server);
    connector.setHost("127.0.0.1");
    connector.setPort(cfg.portOrDefault());
    server.addConnector(connector);

    ServletContextHandler ctx = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
    ctx.setContextPath("/");

    ServletHolder api = new ServletHolder(new ApiServlet(sessions));

    int maxFile = 2 * 1024 * 1024;
    long maxReq = maxFile + (1L * 1024 * 1024);

    api.getRegistration().setMultipartConfig(new MultipartConfigElement(
        System.getProperty("java.io.tmpdir"),
        maxFile,
        maxReq,
        512 * 1024
    ));

    ctx.addServlet(api, "/v1/*");

    server.setHandler(ctx);
    return server;
  }

  private ServerBootstrap() {}
}

