package pl.honeypot.server.alert;

// Sends one plain-text mail to the configured recipients. Throws when the mail server refuses or is unreachable.
@FunctionalInterface
public interface Mailer {
    void send(String subject, String body) throws Exception;
}
