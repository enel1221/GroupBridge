# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM maven:3.9.15-eclipse-temurin-26-alpine@sha256:9b0bc1420b93f3eafb7401dc3030eac01e773d8d709686d3c4ac351fcf6f9f42 AS build
WORKDIR /workspace
COPY pom.xml ./
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp dependency:go-offline
COPY src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp verify \
    && cp target/groupbridge-keycloak-event-listener-*.jar /tmp/groupbridge-keycloak-event-listener.jar

# This intentionally contains only the provider JAR. Consume it as a named
# build context when constructing a pinned, optimized Keycloak runtime image.
FROM scratch
LABEL org.opencontainers.image.title="GroupBridge Keycloak event listener" \
      org.opencontainers.image.description="Keycloak provider JAR OCI artifact" \
      org.opencontainers.image.source="https://github.com/enel1221/GroupBridge"
COPY --from=build /tmp/groupbridge-keycloak-event-listener.jar /provider/groupbridge-keycloak-event-listener.jar
