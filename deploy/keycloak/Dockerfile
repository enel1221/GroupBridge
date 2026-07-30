# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG PROVIDER_IMAGE=groupbridge-keycloak-extension:dev
ARG KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.6.4@sha256:0aae0de7fca85525f727d3354df17896092de8bb26ae4c12d89c77e5df8cbce4

FROM ${PROVIDER_IMAGE} AS provider

FROM ${KEYCLOAK_IMAGE}
COPY --from=provider --chown=1000:0 \
    /provider/groupbridge-keycloak-event-listener.jar \
    /opt/keycloak/providers/groupbridge-keycloak-event-listener.jar
RUN /opt/keycloak/bin/kc.sh build \
    --db=postgres \
    --features=scripts \
    --health-enabled=true \
    --metrics-enabled=true

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
