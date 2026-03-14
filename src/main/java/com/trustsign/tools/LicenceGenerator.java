package com.trustsign.tools;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Vendor-only tool: generate RSA key pair for signing licences, and sign a licence file.
 * Only you (the vendor) run this; the client never gets the private key.
 *
 * Usage:
 *   1. Generate key pair (once):
 *      java -cp trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator genkey [output-dir]
 *      This creates licence-private-key.pem and licence-public-key.pem.
 *      Put licence-public-key.pem in src/main/resources/com/trustsign/ and rebuild the app.
 *      Keep licence-private-key.pem secure; use it only to sign licence files.
 *
 *   2. Sign a licence (when creating a client package):
 *      java -cp trustsign-0.1.0-all.jar com.trustsign.tools.LicenceGenerator sign <durationDays> <private-key.pem> [output.json]
 *      Example: sign 90 licence-private-key.pem config/licence.json
 *      Creates licence.json with the given duration (days from client's first use). Copy it into the client's config directory.
 */
public final class LicenceGenerator {

  public static void main(String[] args) throws Exception {
    if (args == null || args.length < 1) {
      printUsage();
      System.exit(1);
    }
    String cmd = args[0].toLowerCase();
    switch (cmd) {
      case "genkey" -> {
        String outDir = args.length >= 2 ? args[1] : ".";
        genkey(Path.of(outDir));
      }
      case "sign" -> {
        if (args.length < 3) {
          System.err.println("sign requires: durationDays privateKeyPath [outputPath]");
          System.exit(1);
        }
        int days = Integer.parseInt(args[1]);
        Path keyPath = Path.of(args[2]);
        Path outPath = args.length >= 4 ? Path.of(args[3]) : Path.of("licence.json");
        sign(days, keyPath, outPath);
      }
      default -> {
        printUsage();
        System.exit(1);
      }
    }
  }

  private static void printUsage() {
    System.err.println("Usage:");
    System.err.println("  LicenceGenerator genkey [output-dir]");
    System.err.println("  LicenceGenerator sign <durationDays> <private-key.pem> [output.json]");
  }

  private static void genkey(Path outDir) throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair pair = gen.generateKeyPair();

    Path privatePath = outDir.resolve("licence-private-key.pem");
    Path publicPath = outDir.resolve("licence-public-key.pem");

    writePem(privatePath, "PRIVATE KEY", pair.getPrivate().getEncoded(), true);
    writePem(publicPath, "PUBLIC KEY", pair.getPublic().getEncoded(), true);

    System.out.println("Created " + privatePath.toAbsolutePath());
    System.out.println("Created " + publicPath.toAbsolutePath());
    System.out.println("Keep the private key secure. Put the public key in src/main/resources/com/trustsign/ and rebuild.");
  }

  private static void sign(int durationDays, Path privateKeyPath, Path outputPath) throws Exception {
    if (durationDays <= 0) {
      throw new IllegalArgumentException("durationDays must be positive");
    }
    String pem = Files.readString(privateKeyPath);
    PrivateKey privateKey = loadPrivateKeyFromPem(pem);

    String payload = "durationDays=" + durationDays;
    Signature sig = Signature.getInstance("SHA256withRSA");
    sig.initSign(privateKey);
    sig.update(payload.getBytes(StandardCharsets.UTF_8));
    byte[] signature = sig.sign();
    String sigB64 = Base64.getEncoder().encodeToString(signature);

    String json = "{\n  \"durationDays\": " + durationDays + ",\n  \"signature\": \"" + sigB64 + "\"\n}\n";
    Files.createDirectories(outputPath.getParent());
    Files.writeString(outputPath, json);
    System.out.println("Written " + outputPath.toAbsolutePath() + " (duration: " + durationDays + " days from first use)");
  }

  private static void writePem(Path path, String label, byte[] der, boolean overwrite) throws IOException {
    if (Files.exists(path) && !overwrite) {
      throw new IOException("File exists: " + path);
    }
    Files.createDirectories(path.getParent());
    String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(der);
    String pem = "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    Files.writeString(path, pem);
  }

  private static PrivateKey loadPrivateKeyFromPem(String pem) throws Exception {
    pem = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .replaceAll("\\s", "");
    byte[] der = Base64.getDecoder().decode(pem);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
    return KeyFactory.getInstance("RSA").generatePrivate(spec);
  }
}
