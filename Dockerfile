# Build and run minidauth.
#
# MidgardJava is not on Maven Central and this project does not redistribute it, so the build
# expects it in vendor/ and installs it into the image's own local repository. The native library
# rides inside that jar, so nothing else has to be installed to run it.

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src

# Fail here, with a sentence that says what to do, rather than three screens into a Maven trace.
COPY vendor/ vendor/
RUN set -e; \
    jar="$(find vendor -name 'MidgardJava*.jar' ! -name '*sources*' | head -1)"; \
    if [ -z "$jar" ]; then \
      echo "No MidgardJava jar in vendor/. Copy it there, it is not publicly redistributable" >&2; \
      exit 1; \
    fi; \
    mvn -q install:install-file -Dfile="$jar" \
        -DgroupId=org.tide -DartifactId=MidgardJava -Dversion=1.0-SNAPSHOT -Dpackaging=jar

# Dependencies first, so editing sources does not re-resolve the world.
COPY pom.xml .
RUN mvn -q -B dependency:go-offline

COPY src/ src/
RUN mvn -q -B package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app

# Not root: nothing here needs it, and the data directory holds the vendor key.
RUN useradd --system --uid 10001 --create-home minidauth
COPY --from=build /src/target/minidauth.jar ./minidauth.jar
COPY --from=build /src/target/lib/ ./lib/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p /data && chown minidauth /data

USER minidauth
ENV MC_DATA_DIR=/data \
    MC_PORT=8081 \
    SYSTEM_HOME_ORK=https://ork1.tideprotocol.com \
    PAYER_PUBLIC=200000b967a7799ffd4476e1074777ebc83bec23a3843cb2e5ca43c83561802c8e646b \
    THRESHOLD_T=14 \
    THRESHOLD_N=20 \
    MC_POLICY_VERSION=3
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
