package com.trustsign.core;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Parsed payload of a server-signed licence token.
 *
 * Wire format (text):
 *   {base64url(utf8-json)}.{base64url(RSA-SHA256-signature)}
 *
 * The server signs the raw UTF-8 bytes of the base64url-encoded JSON block.
 * The client verifies that signature with the embedded public key before
 * trusting any field.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record LicenceToken(
    @JsonProperty("ver") int version,
    @JsonProperty("jti") String activationId,
    @JsonProperty("sub") String customerId,
    /** SHA-256 hex of strict machine fingerprint (MACs + hostname + OS + CPU). */
    @JsonProperty("fp3") String fingerprintStrict,
    /** SHA-256 hex of medium machine fingerprint (hostname + OS + CPU). */
    @JsonProperty("fp2") String fingerprintMedium,
    /** Unix epoch seconds when the server issued this token. */
    @JsonProperty("iat") long issuedAtEpochSec,
    /** Unix epoch seconds when the licence expires. */
    @JsonProperty("exp") long expiresAtEpochSec
) {
    public long issuedAtMs()  { return issuedAtEpochSec * 1000L;  }
    public long expiresAtMs() { return expiresAtEpochSec * 1000L; }
}
