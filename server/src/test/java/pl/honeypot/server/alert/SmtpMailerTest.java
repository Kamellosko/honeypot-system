package pl.honeypot.server.alert;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class SmtpMailerTest {

    // Minimal SMTP server for one session: answers every command, records commands and the DATA text.
    static final class FakeSmtp implements AutoCloseable {
        final ServerSocket socket = new ServerSocket(0);
        final StringBuilder log = new StringBuilder();
        final Thread thread = new Thread(this::serve);

        FakeSmtp() throws Exception {
            thread.start();
        }

        int port() {
            return socket.getLocalPort();
        }

        private void serve() {
            try (Socket s = socket.accept();
                 BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                 Writer out = new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8)) {
                reply(out, "220 fake ESMTP");
                boolean data = false;
                String line;
                while ((line = in.readLine()) != null) {
                    synchronized (log) {
                        log.append(line).append('\n');
                    }
                    if (data) {
                        if (line.equals(".")) {
                            data = false;
                            reply(out, "250 queued");
                        }
                    } else if (line.startsWith("EHLO") || line.startsWith("HELO")) {
                        reply(out, "250 fake");
                    } else if (line.equals("DATA")) {
                        data = true;
                        reply(out, "354 go");
                    } else if (line.equals("QUIT")) {
                        reply(out, "221 bye");
                        return;
                    } else {
                        reply(out, "250 ok");
                    }
                }
            } catch (Exception ignored) {
                // the test checks what was recorded
            }
        }

        private static void reply(Writer out, String s) throws Exception {
            out.write(s + "\r\n");
            out.flush();
        }

        String log() throws Exception {
            thread.join(5000);
            synchronized (log) {
                return log.toString();
            }
        }

        @Override
        public void close() throws Exception {
            socket.close();
        }
    }

    private static AlertConfig cfg(int port, List<String> to) {
        return new AlertConfig(true, "127.0.0.1", port, false, "", "", "honeypot@x.local", to, 60);
    }

    @Test
    void sendsToAllRecipients() throws Exception {
        try (FakeSmtp smtp = new FakeSmtp()) {
            new SmtpMailer(cfg(smtp.port(), List.of("a@x.pl", "b@y.pl")))
                    .send("[honeypot fs-finanse] BRUTE FORCE 192.0.2.1", "treść ąę");
            String log = smtp.log();
            assertTrue(log.contains("RCPT TO:<a@x.pl>"), log);
            assertTrue(log.contains("RCPT TO:<b@y.pl>"), log);
            assertTrue(log.contains("MAIL FROM:<honeypot@x.local>"), log);
            assertTrue(log.contains("Subject: [honeypot fs-finanse] BRUTE FORCE 192.0.2.1"), log);
        }
    }

    @Test
    void plainSmtpWithoutAuth() throws Exception {
        try (FakeSmtp smtp = new FakeSmtp()) {
            new SmtpMailer(cfg(smtp.port(), List.of("a@x.pl"))).send("s", "b");
            assertFalse(smtp.log().contains("AUTH"));
        }
    }

    @Test
    void connectionRefusedThrows() throws Exception {
        int closedPort;
        try (ServerSocket s = new ServerSocket(0)) {
            closedPort = s.getLocalPort();
        }
        SmtpMailer m = new SmtpMailer(cfg(closedPort, List.of("a@x.pl")));
        assertThrows(Exception.class, () -> m.send("s", "b"));
    }
}
