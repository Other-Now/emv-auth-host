# Multi-stage build: the runtime image carries two binaries and two shared
# libraries, runs as a non-root user, and keeps its database on a volume.
FROM ubuntu:24.04 AS build
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      cmake ninja-build g++ libssl-dev libsqlite3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B /b -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo >/dev/null \
 && cmake --build /b --target eah-server eah-admin

FROM ubuntu:24.04
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libssl3t64 libsqlite3-0 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /b/eah-server /b/eah-admin /usr/local/bin/
USER 10001:10001
VOLUME /data
EXPOSE 8583
ENTRYPOINT ["/usr/local/bin/eah-server"]
CMD ["--db", "/data/host.db", "--bind", "0.0.0.0", "--port", "8583"]
