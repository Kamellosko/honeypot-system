package pl.honeypot.server.alert;

import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;

// Plain SMTP to the configured server; STARTTLS and login only when collector.properties asks for them.
public final class SmtpMailer implements Mailer {

    private static final String TIMEOUT_MS = "10000";

    private final AlertConfig cfg;
    private final Session session;

    public SmtpMailer(AlertConfig cfg) {
        this.cfg = cfg;
        Properties p = new Properties();
        p.setProperty("mail.smtp.host", cfg.host());
        p.setProperty("mail.smtp.port", Integer.toString(cfg.port()));
        p.setProperty("mail.smtp.starttls.enable", Boolean.toString(cfg.starttls()));
        p.setProperty("mail.smtp.starttls.required", Boolean.toString(cfg.starttls()));
        p.setProperty("mail.smtp.auth", Boolean.toString(!cfg.user().isEmpty()));
        p.setProperty("mail.smtp.connectiontimeout", TIMEOUT_MS);
        p.setProperty("mail.smtp.timeout", TIMEOUT_MS);
        p.setProperty("mail.smtp.writetimeout", TIMEOUT_MS);
        this.session = Session.getInstance(p);
    }

    @Override
    public void send(String subject, String body) throws Exception {
        MimeMessage m = new MimeMessage(session);
        m.setFrom(new InternetAddress(cfg.from()));
        for (String to : cfg.to()) {
            m.addRecipient(Message.RecipientType.TO, new InternetAddress(to));
        }
        m.setSubject(subject, "UTF-8");
        m.setText(body, "UTF-8");
        if (cfg.user().isEmpty()) {
            Transport.send(m);
        } else {
            Transport.send(m, cfg.user(), cfg.password());
        }
    }
}
