package pl.honeypot.server.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

// Append-only JSON Lines log: one record per line, UTF-8.
// Each appended line gets a generated id and a received_at timestamp.
// Writes are serialized so concurrent request threads don't interleave lines.
public final class JsonlLog {

    private final Path file;
    private final ObjectMapper mapper;
    private final String idField;
    private final AtomicLong seq;
    private final Object lock = new Object();

    public JsonlLog(Path file, ObjectMapper mapper, String idField) throws IOException {
        this.file = file;
        this.mapper = mapper;
        this.idField = idField;
        Path parent = file.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        // Seed the id counter from the records already on disk so ids stay
        // unique and roughly monotonic across restarts.
        long existing = 0;
        if (Files.exists(file)) {
            try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
                existing = lines.filter(l -> !l.isBlank()).count();
            }
        }
        this.seq = new AtomicLong(existing);
    }

    // Serializes the record, stamps it with the next id and received_at,
    // appends it as one line, and returns the generated id.
    public long append(Object record) {
        long id = seq.incrementAndGet();
        ObjectNode node = mapper.valueToTree(record);
        node.put(idField, id);
        node.put("received_at", DateTimeFormatter.ISO_INSTANT
                .format(Instant.now().truncatedTo(ChronoUnit.SECONDS)));

        String line;
        try {
            line = mapper.writeValueAsString(node);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        synchronized (lock) {
            try (Writer w = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                w.write(line);
                w.write('\n');
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return id;
    }

    // Reads every record back, in the order they were written (oldest first).
    // Blank or unparseable lines are skipped. Runs under the write lock so it
    // never observes a half-written line.
    public List<JsonNode> read() {
        synchronized (lock) {
            if (!Files.exists(file)) {
                return List.of();
            }
            List<JsonNode> out = new ArrayList<>();
            try (var lines = Files.lines(file, StandardCharsets.UTF_8)) {
                lines.forEach(l -> {
                    if (l.isBlank()) {
                        return;
                    }
                    try {
                        out.add(mapper.readTree(l));
                    } catch (IOException ignored) {
                        // Skip a corrupt line rather than failing the whole read.
                    }
                });
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return out;
        }
    }
}
