# =============================================================================
# TrustSign ProGuard configuration
# Target: Spring Boot 3.3.5 + PKCS#11 signing service compiled to Java 17
# =============================================================================

# ── Class-file attributes to retain ──────────────────────────────────────────
# *Annotation*  — Spring/Jackson/iText scan for annotations at runtime.
# Signature     — Generic type signatures; needed by Jackson for type binding.
# Exceptions    — Declared checked exceptions on API methods.
# InnerClasses  — Required for nested/inner classes to be loaded correctly.
# EnclosingMethod — Companion to InnerClasses for anonymous / local classes.
# Record        — Java 16+ RecordAttribute; Jackson uses it to deserialise
#                 records by constructor parameter order.
# LineNumberTable — Keeps line numbers in stack traces so they can be
#                   correlated with the ProGuard mapping file.
-keepattributes *Annotation*, Signature, Exceptions, InnerClasses, EnclosingMethod, Record, LineNumberTable, StackMapTable

# Rename the SourceFile attribute to a generic string so stack traces show
# line numbers (useful for debugging) but not the original file names.
-renamesourcefileattribute SourceFile

# Disable ProGuard's bytecode optimiser.  Spring Boot relies on CGLIB for AOP
# proxies; aggressive optimisation can rewrite code in ways that break cglib.
-dontoptimize

# Suppress all library-resolution warnings.  Many dependencies pull in optional
# APIs (e.g. servlet containers, SLF4J bridges) that are not on the classpath
# during obfuscation but are always present at runtime.
-dontwarn **

# The JDK module files (GraalVM 25 / JDK 25) use bytecode version 69, which
# ProGuard 7.5 cannot parse.  We omit JDK modules from -libraryjars entirely
# and tell ProGuard to ignore missing references to platform classes.
# The JVM performs its own full verification when the fat JAR is launched, so
# skipping ProGuard's class-hierarchy check for JDK types is safe.
# Note: -dontpreverify was previously used here but caused ProGuard to strip
# StackMapTable attributes, breaking JVM bytecode verification on Java 7+ classes.
-ignorewarnings

# =============================================================================
# KEEP rules — what must NOT be renamed or removed
# =============================================================================

# ── 1. Entry point ───────────────────────────────────────────────────────────
# The Spring Boot fat-JAR manifest's Start-Class attribute is set to this by
# the bootJar task; the class name must survive obfuscation unchanged.
-keep class com.trustsign.server.Main {
    public static void main(java.lang.String[]);
}

# ── 2. Spring Boot application class ─────────────────────────────────────────
# @SpringBootApplication defines the root package for component scanning.
# If the class is renamed its package changes, and Spring no longer scans
# com.trustsign.server.** for beans — keep name AND all members.
-keep @org.springframework.boot.autoconfigure.SpringBootApplication class * { *; }

# ── 3. Spring @Configuration classes ─────────────────────────────────────────
# Spring instantiates @Configuration classes by name via CGLIB subclassing.
# The class name must be stable, and all @Bean factory methods must remain
# callable (Spring invokes them by reflection).
-keep @org.springframework.context.annotation.Configuration class * { *; }

# ── 4. Spring web controllers (@RestController) ───────────────────────────────
# Spring MVC registers handler methods discovered on @RestController beans.
# Keep the class name (bean registry) and all @Mapping-annotated methods
# (Spring invokes them via reflection using the Method object).
-keep @org.springframework.web.bind.annotation.RestController class * { *; }
-keepclassmembers class * {
    @org.springframework.web.bind.annotation.RequestMapping *;
    @org.springframework.web.bind.annotation.GetMapping    *;
    @org.springframework.web.bind.annotation.PostMapping   *;
    @org.springframework.web.bind.annotation.DeleteMapping *;
}

# ── 5. Spring bean and injection metadata ─────────────────────────────────────
# Spring resolves @Bean, @Autowired and @Value by annotation scanning at
# startup; if the annotations are stripped the context fails to start.
-keepclassmembers class * {
    @org.springframework.context.annotation.Bean *;
    @org.springframework.beans.factory.annotation.Autowired *;
    @org.springframework.beans.factory.annotation.Value    *;
}

# ── 6. Servlet / Filter lifecycle callbacks ───────────────────────────────────
# Tomcat calls these methods by name via the Servlet API contract.
# Only the method signatures defined by the API need to be preserved; all
# private helper methods in the implementation can be renamed freely.
-keepclassmembers class * extends jakarta.servlet.http.HttpServlet {
    public void doGet(jakarta.servlet.http.HttpServletRequest, jakarta.servlet.http.HttpServletResponse);
    public void doPost(jakarta.servlet.http.HttpServletRequest, jakarta.servlet.http.HttpServletResponse);
    public void service(jakarta.servlet.http.HttpServletRequest, jakarta.servlet.http.HttpServletResponse);
    public void init(jakarta.servlet.ServletConfig);
    public void destroy();
}
-keepclassmembers class * extends org.springframework.web.filter.OncePerRequestFilter {
    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest, jakarta.servlet.http.HttpServletResponse, jakarta.servlet.FilterChain);
    public boolean shouldNotFilter(jakarta.servlet.http.HttpServletRequest);
}

# ── 7. Jackson models — all fields + accessor names must survive ──────────────
# Java records store component names in the Record class-file attribute.
# ProGuard updates that attribute when it renames fields.  If private fields
# are renamed to the same short name (especially with -overloadaggressively),
# Jackson's record creator sees duplicate property names and throws.
# Keeping ALL members (private fields + public accessors) avoids this.
-keepclassmembers class com.trustsign.core.AgentConfig    { *; }
-keepclassmembers class com.trustsign.core.AgentConfig$** { *; }
-keepclassmembers class com.trustsign.core.LicenceToken   { *; }

# Pkcs11Token.CertItem is returned directly (as a List) in GET /pki/certificates'
# JSON body — Jackson must reflect its record components to serialize it.
-keepclassmembers class com.trustsign.core.Pkcs11Token$CertItem { *; }

# SignedFileAnalyzer.Result (and the VerifiedMatch/Attempt records nested inside
# its List fields) is returned directly as the JSON body of the debug-analysis
# endpoint.
-keepclassmembers class com.trustsign.core.SignedFileAnalyzer$** { *; }

# PdfVerifyService.Result (and its nested SignatureReport/CertificateDetails
# records) is returned directly as the JSON body of /verify-pdf. Pre-existing
# gap found and fixed alongside adding verify-xml/verify-excel, which follow
# the same direct-serialization pattern.
-keepclassmembers class com.trustsign.core.PdfVerifyService$** { *; }

# XmlVerifyService.Result / SignatureReport / CertificateDetails: same
# direct-Jackson-serialization pattern for /verify-xml.
-keepclassmembers class com.trustsign.core.XmlVerifyService$** { *; }

# ExcelVerifyService.Result / SignatureReport / CertificateDetails: same
# direct-Jackson-serialization pattern for /verify-excel.
-keepclassmembers class com.trustsign.core.ExcelVerifyService$** { *; }

# ── 8. Public cross-package API ───────────────────────────────────────────────
# These are concrete methods called from obfuscated code in other packages.
# ProGuard updates references consistently, but the member signatures must
# be stable because they are referenced from kept (server) classes.
-keepclassmembers class com.trustsign.core.LicenceEnforcer {
    public ** check();
    public static ** loadPublicKeyFromPem(java.io.InputStream);
}
-keepclassmembers class com.trustsign.core.LicenceEnforcer$Result { public *; }
-keepclassmembers class com.trustsign.core.SessionManager {
    public ** createSessionMinutes(int);
    public void requireValid(java.lang.String);
}
-keepclassmembers class com.trustsign.core.SessionManager$Session { public *; }
-keepclassmembers class com.trustsign.core.ConfigLoader {
    public static ** load(java.io.File);
}

# =============================================================================
# OBFUSCATION settings
# =============================================================================

# Flatten ALL com.trustsign.core/hsm and our custom com.itextpdf.signatures
# classes into a single short package.  After this transformation a decompiler
# sees ts.A, ts.B … instead of the original meaningful package hierarchy.
# Classes protected by a -keep rule (server package) are NOT repackaged.
-repackageclasses 'ts'

# Prevent mixed-case class names (ts.a vs ts.A). On case-insensitive file
# systems (macOS APFS, Windows NTFS) extracting the obfuscated JAR would
# let A.class overwrite a.class, causing ClassNotFoundException at runtime.
-dontusemixedcaseclassnames

# Write the name-mapping file so internal stack traces can be de-obfuscated
# with ProGuard's ReTrace tool: retrace build/proguard-mapping.txt stacktrace.txt
-printmapping build/proguard-mapping.txt
