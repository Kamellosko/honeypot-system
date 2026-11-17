package pl.honeypot.server.store;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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
import java.util.Arrays;
import java.util.Set;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.function.Predicate;

// Append-only JSON Lines log: one record per line, UTF-8.
// Each appended line gets a generated id and a received_at timestamp.
// Writes are serialized so concurrent request threads don't interleave lines.
public final class JsonlLog {

    private static final int CHUNK_BYTES = 64 * 1024;

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
        // Seed the id counter from the highest id already on disk, so ids stay
        // unique across restarts even when a failed append consumed one.
        this.seq = new AtomicLong();
        forEach(n -> seq.accumulateAndGet(n.path(idField).asLong(), Math::max));
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
                long before = ch.size();
                try {
                    while (bytes.hasRemaining()) {
                        ch.write(bytes);
                    }
                    ch.force(false);   // 2xx is only sent after the line is on disk
                } catch (IOException e) {
                    // Cut off a partial line, otherwise the retry is glued to it.
                    try {
                        ch.truncate(before);
                    } catch (IOException t) {
                        e.addSuppressed(t);
                    }
                    throw e;
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return node;
    }

    // Visits every record in the order they were written (oldest first), one
    // line at a time. Blank or unparseable lines are skipped.
    public void forEach(Consumer<JsonNode> visitor) {
        if (!Files.exists(file)) {
            return;
        }
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    JsonNode n = mapper.readTree(line);
                    if (n != null) {
                        visitor.accept(n);
                    }
                } catch (IOException ignored) {
                    // Skip a corrupt line rather than failing the whole read.
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // Visits records newest first by reading the file backwards in chunks, so a
    // short query never loads the whole file. Stops as soon as the visitor
    // returns false. The file only grows, so we take its length under the lock
    // and read that prefix outside it. Blank or unparseable lines are skipped.
    public void readNewestFirst(Predicate<JsonNode> visitor) {
        long end;
        synchronized (lock) {
            if (!Files.exists(file)) {
                return;
            }
            try {
                end = Files.size(file);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        try (RandomAccessFile f = new RandomAccessFile(file.toFile(), "r")) {
            long pos = end;
            byte[] tail = new byte[0];   // start of a line whose beginning is still unread
            while (pos > 0) {
                int n = (int) Math.min(CHUNK_BYTES, pos);
                pos -= n;
                byte[] buf = new byte[n + tail.length];
                f.seek(pos);
                f.readFully(buf, 0, n);
                System.arraycopy(tail, 0, buf, n, tail.length);
                int lineEnd = buf.length;
                for (int k = buf.length - 1; k >= 0; k--) {
                    if (buf[k] == '\n') {
                        if (!emit(buf, k + 1, lineEnd, visitor)) {
                            return;
                        }
                        lineEnd = k;
                    }
                }
                tail = Arrays.copyOfRange(buf, 0, lineEnd);
            }
            emit(tail, 0, tail.length, visitor);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // Parses buf[from, to) as one record and passes it on. Returns false when the visitor is done.
    private boolean emit(byte[] buf, int from, int to, Predicate<JsonNode> visitor) {
        if (to <= from) {
            return true;
        }
        try {
            JsonNode n = mapper.readTree(new String(buf, from, to - from, StandardCharsets.UTF_8));
            return n == null || visitor.test(n);
        } catch (IOException ignored) {
            return true;   // skip a corrupt line
        }
    }
}
