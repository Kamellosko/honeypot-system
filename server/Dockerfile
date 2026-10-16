# Build stage
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q dependency:go-offline
COPY src ./src
RUN mvn -q package -DskipTests

# Runtime stage (AlmaLinux, same as the rest of the lab)
FROM almalinux:9
RUN dnf install -y java-21-openjdk-headless && dnf clean all \
    && useradd --system --no-create-home honeypot \
    && mkdir -p /var/lib/honeypot-server && chown honeypot /var/lib/honeypot-server
COPY --from=build /src/target/honeypot-server.jar /opt/honeypot-server/honeypot-server.jar
COPY config/server.properties /etc/honeypot-server/server.properties
COPY config/sensors.json /etc/honeypot-server/sensors.json
RUN sed -i -e 's|^sensors.file=.*|sensors.file=/etc/honeypot-server/sensors.json|' \
           -e 's|^data.dir=.*|data.dir=/var/lib/honeypot-server|' \
           /etc/honeypot-server/server.properties
USER honeypot
EXPOSE 8000
VOLUME /var/lib/honeypot-server
ENTRYPOINT ["java", "-jar", "/opt/honeypot-server/honeypot-server.jar", "/etc/honeypot-server/server.properties"]
