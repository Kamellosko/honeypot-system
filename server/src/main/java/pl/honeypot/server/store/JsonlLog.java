package pl.honeypot.server.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
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
        repairTail(file);
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

    // After a crash the last line may be cut off. Drop the fragment, otherwise the
    // next record would be glued to it and both would be unreadable.
    private static void repairTail(Path file) throws IOException {
        if (!Files.exists(file) || Files.size(file) == 0) {
            return;
        }
        try (RandomAccessFile f = new RandomAccessFile(file.toFile(), "rw")) {
            long len = f.length();
            f.seek(len - 1);
            if (f.read() == '\n') {
                return;
            }
            long pos = len - 1;
            while (pos > 0) {
                f.seek(pos - 1);
                if (f.read() == '\n') {
                    break;
                }
                pos--;
            }
            f.setLength(pos);
        }
    }

    // Serializes the record, stamps it with the next id and received_at,
    // appends it as one line (fsynced), and returns the stamped record.
    public ObjectNode append(Object record) {
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

        ByteBuffer bytes = ByteBuffer.wrap((line + "\n").getBytes(StandardCharsets.UTF_8));
        synchronized (lock) {
            // Owner-only: reports contain file contents and log excerpts.
            try (FileChannel ch = FileChannel.open(file,
                    Set.of(StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(
                            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)))) {
                while (bytes.hasRemaining()) {
                    ch.write(bytes);
                }
                ch.force(false);   // 2xx is only sent after the line is on disk
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return node;
    }

    // Reads every record back, in the order they were written (oldest first).
    // The file only grows, so we take its length under the lock and parse that
    // prefix outside it: a slow reader never blocks new reports.
    // Blank or unparseable lines are skipped.
    public List<JsonNode> read() {
        long size;
        synchronized (lock) {
            if (!Files.exists(file)) {
                return List.of();
            }
            try {
                size = Files.size(file);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        byte[] data = new byte[(int) Math.min(size, Integer.MAX_VALUE - 8)];
        try (RandomAccessFile f = new RandomAccessFile(file.toFile(), "r")) {
            f.readFully(data);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        List<JsonNode> out = new ArrayList<>();
        int start = 0;
        for (int k = 0; k < data.length; k++) {
            if (data[k] != '\n') {
                continue;
            }
            if (k > start) {
                try {
                    out.add(mapper.readTree(new String(data, start, k - start, StandardCharsets.UTF_8)));
                } catch (IOException ignored) {
                    // Skip a corrupt line rather than failing the whole read.
                }
            }
            start = k + 1;
        }
        return out;
    }
}
