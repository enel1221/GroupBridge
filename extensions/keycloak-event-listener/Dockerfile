# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM maven:3.9.11-eclipse-temurin-21-alpine@sha256:922927df2c662cdd47ddb116443d6bec4696cfae3de1a0ddac8fcc7b87ce61ae AS build
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
