FROM http-garden-soil:latest

# The soil provides a C toolchain and a sanitizer environment meant for the
# targets that build with it. Zig ships its own toolchain, so the fetch below
# adds only what the tarball needs and every build step unsets the soil's
# CC/CFLAGS — the same thing the pingora target does for cargo, and for the
# same reason: those flags are clang's, and Zig does not take them.
RUN apt -y update \
 && apt -y install --no-install-recommends curl xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Pinned rather than "latest": zoxy declares `minimum_zig_version` and the
# language is still moving, so the toolchain is part of what this image
# reproduces. Both tarballs are checksummed — a silent swap upstream would
# otherwise become a silent change in what the Garden is testing.
ARG ZIG_VERSION=0.16.0
RUN arch="$(uname -m)" \
 && case "$arch" in \
      aarch64) zig_sha='ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17' ;; \
      x86_64)  zig_sha='70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00' ;; \
      *) echo "no pinned zig for $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-${arch}-linux-${ZIG_VERSION}.tar.xz" \
 && printf '%s  /tmp/zig.tar.xz\n' "$zig_sha" | sha256sum -c - \
 && mkdir -p /opt/zig \
 && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
 && rm /tmp/zig.tar.xz
ENV PATH="/opt/zig:$PATH"

ARG APP_REPO
RUN git clone --recurse-submodules "$APP_REPO"

# ReleaseSafe is what zoxy ships, and it is also the right mode to be
# differentially tested in: TIGER_STYLE puts at least two assertions in every
# function, so an invariant this proxy believes about its own state becomes a
# crash the Garden observes rather than a wrong answer it has to notice.
ARG APP_BRANCH
ARG APP_VERSION
RUN cd /app/zoxy \
 && git pull origin "$APP_BRANCH" \
 && git checkout "$APP_VERSION" \
 && unset CC CXX CFLAGS CXXFLAGS LDFLAGS \
 && zig build -Doptimize=ReleaseSafe --prefix /usr/local

ARG CONFIG_FILE
COPY $CONFIG_FILE /app/zoxy.json

ARG BACKEND_HOST=127.0.0.1
ARG BACKEND_PORT=56062
RUN sed -i -e "s/BACKEND_HOST_PLACEHOLDER/$BACKEND_HOST/g" -e "s/BACKEND_PORT_PLACEHOLDER/$BACKEND_PORT/g" /app/zoxy.json

ARG START_SCRIPT
COPY $START_SCRIPT ./start.sh
CMD ["./start.sh"]
