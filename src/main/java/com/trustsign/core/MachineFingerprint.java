package com.trustsign.core;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * Collects hardware-bound machine signals at three strictness levels used for
 * machine-binding the licence token and encrypting the licence storage file.
 *
 * Level 3 (strict)  — MACs + hostname + OS + CPU count
 *   Embedded in the signed token by the activation server.
 *   Fails if a NIC is replaced/removed.
 *
 * Level 2 (medium)  — hostname + OS + CPU count
 *   Fallback embedded in the signed token. Passes even after a NIC swap
 *   (VM restart, hardware upgrade) as long as the machine identity is the same.
 *
 * Level 1 (stable)  — hostname + OS
 *   Used ONLY as the PBKDF2 password for local-file encryption key derivation.
 *   The stable level is NOT embedded in the token; it is recomputed live on
 *   every run. A different hostname means a different decryption key, so the
 *   encrypted licence file cannot be decrypted on another machine.
 */
public final class MachineFingerprint {

    private MachineFingerprint() {}

    /**
     * Strict fingerprint: SHA-256(MACs + hostname + OS + CPU count).
     * Sent to the activation server; embedded verbatim in the signed token.
     */
    public static String computeStrict() {
        try {
            List<String> parts = new ArrayList<>();
            parts.add("m:" + collectMacAddresses());
            parts.add("h:" + resolveHostname());
            parts.add("o:" + osSignal());
            parts.add("c:" + Runtime.getRuntime().availableProcessors());
            Collections.sort(parts);
            return sha256hex(String.join("|", parts));
        } catch (Exception e) {
            throw new RuntimeException("Cannot compute strict machine fingerprint", e);
        }
    }

    /**
     * Medium fingerprint: SHA-256(hostname + OS + CPU count).
     * Sent to the server as a fallback for machines where the MAC may change
     * (VM restart, NIC upgrade). The server embeds both fp3 and fp2 in the token
     * so the client can match on either.
     */
    public static String computeMedium() {
        try {
            return sha256hex(
                "h:" + resolveHostname() + "|o:" + osSignal()
                + "|c:" + Runtime.getRuntime().availableProcessors());
        } catch (Exception e) {
            throw new RuntimeException("Cannot compute medium machine fingerprint", e);
        }
    }

    /**
     * Stable fingerprint: SHA-256(hostname + OS).
     * Used as the PBKDF2 password for deriving the AES-256-GCM encryption key
     * that protects the local licence storage file. This ensures the file cannot
     * be decrypted on a machine with a different hostname or OS.
     */
    public static String computeStable() {
        try {
            return sha256hex("h:" + resolveHostname() + "|o:" + osSignal());
        } catch (Exception e) {
            throw new RuntimeException("Cannot compute stable machine fingerprint", e);
        }
    }

    // -------------------------------------------------------------------------

    private static String collectMacAddresses() throws Exception {
        TreeSet<String> macs = new TreeSet<>();
        Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
        if (ifaces != null) {
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (iface.isLoopback() || iface.isVirtual() || !iface.isUp()) {
                    continue;
                }
                byte[] mac = iface.getHardwareAddress();
                if (mac != null && mac.length == 6) {
                    macs.add(HexFormat.of().formatHex(mac));
                }
            }
        }
        return macs.isEmpty() ? "none" : String.join(",", macs);
    }

    public static String resolveHostname() {
        try {
            return InetAddress.getLocalHost().getHostName().toLowerCase(Locale.ROOT);
        } catch (Exception ignored) {}
        String cn = System.getenv("COMPUTERNAME");
        if (cn != null && !cn.isBlank()) return cn.toLowerCase(Locale.ROOT);
        String hn = System.getenv("HOSTNAME");
        if (hn != null && !hn.isBlank()) return hn.toLowerCase(Locale.ROOT);
        return "unknown";
    }

    private static String osSignal() {
        return System.getProperty("os.name", "unknown").toLowerCase(Locale.ROOT)
            + ":" + System.getProperty("os.arch", "unknown").toLowerCase(Locale.ROOT);
    }

    static String sha256hex(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(md.digest(input.getBytes(StandardCharsets.UTF_8)));
    }
}
