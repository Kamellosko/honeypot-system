package pl.honeypot.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class SchemaExamplesTest {
    private static final ObjectMapper M = new ObjectMapper();

    private static JsonSchema schema() throws IOException {
        JsonNode node = M.readTree(Files.readString(Path.of("../docs/schema/event-v2.schema.json")));
        return JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012).getSchema(node);
    }

    private static List<Path> examples() throws IOException {
        List<Path> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(Path.of("examples"), "report-*.json")) {
            ds.forEach(out::add);
        }
        return out;
    }

    @Test
    void agentOutputExamplesMatchSchema() throws IOException {
        JsonSchema schema = schema();
        List<Path> files = examples();
        assertTrue(files.size() >= 4, "expected examples captured from the agent");
        for (Path f : files) {
            var errors = schema.validate(M.readTree(Files.readString(f)));
            assertTrue(errors.isEmpty(), f + ": " + errors);
        }
    }

    @Test
    void schemaRejectsBadSeverity() throws IOException {
        ObjectNode doc = (ObjectNode) M.readTree(Files.readString(Path.of("examples/report-heartbeat.json")));
        ((ObjectNode) doc.get("event")).put("severity", "bogus");
        assertFalse(schema().validate(doc).isEmpty());
    }

    @Test
    void schemaRejectsMissingEvent() throws IOException {
        ObjectNode doc = (ObjectNode) M.readTree(Files.readString(Path.of("examples/report-heartbeat.json")));
        doc.remove("event");
        assertFalse(schema().validate(doc).isEmpty());
    }

    @Test
    void schemaAllowsUnknownEventType() throws IOException {
        ObjectNode doc = (ObjectNode) M.readTree(Files.readString(Path.of("examples/report-heartbeat.json")));
        ((ObjectNode) doc.get("event")).put("type", "future.thing");
        assertEquals(0, schema().validate(doc).size());
    }
}
