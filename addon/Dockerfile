ARG BUILD_FROM
FROM ${BUILD_FROM}

# The Supervisor builds an add-on with the add-on directory as its context, so
# the application cannot be COPYed from the repository root. Fetching a pinned
# tarball keeps one copy of the source instead of a vendored second one that
# quietly drifts out of step.
# Pinned to the tag matching config.yaml's version, not a branch. A moving
# branch keeps the same URL, so the build cache would happily reuse a layer
# holding last week's code; bumping the version changes the URL and the fetch
# re-runs on its own.
ARG AURORAIRC_REF=v1.2.0
# The commit that release is cut from, so a device can still build the moment
# the version lands on main - before the tag is pushed, or if it never is.
# A sha, not a branch: it is the same immutable tree the tag would name, so
# nothing here can quietly drift onto later work.
ARG AURORAIRC_COMMIT=bf5393136b65641d1187baf3c9b541188722c4e3
ARG AURORAIRC_URL=https://codeload.github.com/aurora-silicon/aurorairc/tar.gz/refs/tags/${AURORAIRC_REF}
ARG AURORAIRC_FALLBACK=https://codeload.github.com/aurora-silicon/aurorairc/tar.gz/${AURORAIRC_COMMIT}

# python3 is the whole dependency list. tzdata so timestamps follow the
# timezone Home Assistant passes in rather than sitting in UTC.
RUN apk add --no-cache python3 tzdata

# Downloaded whole before it is unpacked: piping wget straight into tar would
# feed it a truncated stream if the first URL 404s part way through.
RUN mkdir -p /opt/aurorairc \
 && ( wget -qO /tmp/src.tgz "${AURORAIRC_URL}" \
      || ( echo "tag ${AURORAIRC_REF} is not published; using pinned commit" \
           && wget -qO /tmp/src.tgz "${AURORAIRC_FALLBACK}" ) ) \
 && tar xzf /tmp/src.tgz --strip-components=1 -C /opt/aurorairc \
 && rm -f /tmp/src.tgz \
 && rm -rf /opt/aurorairc/addon /opt/aurorairc/repository.yaml \
 && python3 -c "import ast,pathlib,sys; [ast.parse(p.read_text()) for p in pathlib.Path('/opt/aurorairc').rglob('*.py')]" \
 && echo "source parses"

COPY rootfs /

RUN chmod +x /etc/s6-overlay/scripts/import \
             /etc/s6-overlay/s6-rc.d/aurorairc-serve/run \
             /etc/s6-overlay/s6-rc.d/aurorairc-serve/finish \
             /etc/s6-overlay/s6-rc.d/aurorairc-live/run \
             /etc/s6-overlay/s6-rc.d/aurorairc-live/finish

LABEL io.hass.name="AuroraIRC" io.hass.type="addon" io.hass.version="1.2.0"
