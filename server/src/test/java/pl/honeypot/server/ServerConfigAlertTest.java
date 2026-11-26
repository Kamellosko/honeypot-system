package pl.honeypot.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class ServerConfigAlertTest {

    private static Path config(String extra) throws Exception {
        Path dir = Files.createTempDirectory("hp-cfg");
        Path ks = Files.writeString(dir.resolve("ks.p12"), "x");   // load() only checks that the file exists
        return Files.writeString(dir.resolve("c.properties"),
                "server.keystore=" + ks + "\nserver.keystore.password=changeit\n" + extra);
    }

    @Test
    void loadsAlertSection() throws Exception {
        ServerConfig cfg = ServerConfig.load(config(
                "alert.enabled=true\nalert.smtp.host=192.168.56.1\nalert.from=honeypot@x.local\nalert.to=pawel@localhost\n"));
        assertTrue(cfg.alert().enabled());
        assertEquals("192.168.56.1", cfg.alert().host());
        assertEquals(List.of("pawel@localhost"), cfg.alert().to());
    }

    @Test
    void alertDisabledByDefault() throws Exception {
        assertFalse(ServerConfig.load(config("")).alert().enabled());
    }
}
