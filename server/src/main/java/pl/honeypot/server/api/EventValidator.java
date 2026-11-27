package pl.honeypot.server.api;

import com.fasterxml.jackson.databind.JsonNode;
import io.javalin.http.BadRequestResponse;
import java.net.InetAddress;
import java.util.Set;
import java.util.regex.Pattern;

// Checks the "event" block of a schema_version 2 report. Unknown event.type values are allowed
// (the agent may be newer than the server); only the shape and the enums are enforced.
final class EventValidator {

    private static final Pattern NAME = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");
    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern IPV6_CHARS = Pattern.compile("^[0-9a-fA-F:.]{2,45}$");
    private static final Set<String> SEVERITY = Set.of("info", "low", "medium", "high");
    private static final Set<String> OUTCOME = Set.of("success", "failure", "unknown");
    private static final int MAX_USER = 256;
    private static final int MAX_PASSWORD = 1024;
    private static final int MAX_PASSWORD_B64 = 4096;

    private EventValidator() {
    }

    static void validate(JsonNode event) {
        if (event == null || !event.isObject()) {
            throw new BadRequestResponse("event block required for schema_version 2");
        }
        requirePattern(event, "category");
        requirePattern(event, "type");
        requireEnum(event, "severity", SEVERITY);
        requireEnum(event, "outcome", OUTCOME);
        endpoint(event.get("src"), "src");
        endpoint(event.get("dst"), "dst");
        JsonNode user = event.get("user");
        if (user != null && !user.isNull()) {
            JsonNode name = user.get("name");
            if (name == null || !name.isTextual() || name.asText().length() > MAX_USER) {
                throw new BadRequestResponse("invalid event.user.name");
            }
        }
        credential(event.get("credential"));
        detail(event.get("detail"));
    }

    // Optional password of an auth.attempt: {"password": text|null, "password_base64": text}.
    private static void credential(JsonNode c) {
        if (c == null || c.isNull()) {
            return;
        }
        JsonNode pw = c.get("password");
        JsonNode b64 = c.get("password_base64");
        if (!c.isObject()
                || (pw != null && !pw.isNull() && (!pw.isTextual() || pw.asText().length() > MAX_PASSWORD))
                || (b64 != null && !b64.isNull() && (!b64.isTextual() || b64.asText().length() > MAX_PASSWORD_B64))) {
            throw new BadRequestResponse("invalid event.credential");
        }
    }

    // Optional detail of a net.scan: {"ports": int >= 1, "scan": name, "window_seconds": int >= 1}.
    private static void detail(JsonNode d) {
        if (d == null || d.isNull()) {
            return;
        }
        JsonNode scan = d.get("scan");
        if (!d.isObject()
                || !positiveInt(d.get("ports"))
                || !positiveInt(d.get("window_seconds"))
                || (scan != null && !scan.isNull() && (!scan.isTextual() || !NAME.matcher(scan.asText()).matches()))) {
            throw new BadRequestResponse("invalid event.detail");
        }
    }

    // Absent or null passes; anything else must be an integer >= 1.
    private static boolean positiveInt(JsonNode n) {
        return n == null || n.isNull() || (n.isIntegralNumber() && n.canConvertToInt() && n.asInt() >= 1);
    }

    private static void requirePattern(JsonNode event, String field) {
        JsonNode v = event.get(field);
        if (v == null || !v.isTextual() || !NAME.matcher(v.asText()).matches()) {
            throw new BadRequestResponse("invalid event." + field);
        }
    }

    private static void requireEnum(JsonNode event, String field, Set<String> allowed) {
        JsonNode v = event.get(field);
        if (v == null || !v.isTextual() || !allowed.contains(v.asText())) {
            throw new BadRequestResponse("invalid event." + field);
        }
    }

    private static void endpoint(JsonNode ep, String name) {
        if (ep == null || ep.isNull()) {
            return;
        }
        JsonNode ip = ep.get("ip");
        if (ip != null && !ip.isNull() && (!ip.isTextual() || !validIp(ip.asText()))) {
            throw new BadRequestResponse("invalid event." + name + ".ip");
        }
        JsonNode port = ep.get("port");
        if (port != null && !port.isNull() && (!port.canConvertToInt() || port.asInt() < 1 || port.asInt() > 65535)) {
            throw new BadRequestResponse("invalid event." + name + ".port");
        }
    }

    // Literal addresses only, never a DNS lookup.
    private static boolean validIp(String s) {
        var m = IPV4.matcher(s);
        if (m.matches()) {
            for (int i = 1; i <= 4; i++) {
                if (Integer.parseInt(m.group(i)) > 255) {
                    return false;
                }
            }
            return true;
        }
        if (!s.contains(":") || !IPV6_CHARS.matcher(s).matches()) {
            return false;
        }
        try {
            InetAddress.getByName(s);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
