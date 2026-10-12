# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Deepsand runtime image
#
# This image is the *entire* universe the contained DeepCode instance can see.
# Everything outside of the bind mounts Deepsand attaches at container start is
# unreachable, because it simply does not exist inside this image.
#
# Build:  docker build -t deepsand/runtime:dev runtime/
# ---------------------------------------------------------------------------
ARG NODE_VERSION=22
FROM node:${NODE_VERSION}-bookworm-slim

LABEL org.opencontainers.image.title="Deepsand DeepCode runtime"
LABEL org.opencontainers.image.description="Sandboxed DeepCode CLI runtime managed by the Deepsand desktop app."
LABEL org.opencontainers.image.source="https://github.com/L1lith/DeepCode-Sandbox"
LABEL org.opencontainers.image.licenses="MIT"
LABEL deepsand.runtime.contract="1"

ARG DEEPCODE_CLI_VERSION=latest
ARG INSTALL_BUILD_TOOLS=0
# The tool selection and the DeepCode refresh are declared further down, next to the
# steps that use them. An ARG invalidates every instruction *after* it, so declaring
# them here made a change to one tool rebuild the base image, and made the DeepCode
# refresh -- which changes on every build by design -- rebuild everything below it.
# See "Selected tools" and "DeepCode CLI" near the end of this file.
ARG DEBIAN_FRONTEND=noninteractive

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    TZ=UTC \
    TERM=xterm-256color \
    HOME=/home/deepcode \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_CACHE=/tmp/.npm \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEEPSAND_IMAGE_CONTRACT=1

# ---------------------------------------------------------------------------
# Base toolchain
#
# Only what the runtime itself needs. Everything an operator can select -- git, jq,
# ripgrep, zip, wget and the rest -- is installed by the "Selected tools" step from the
# project's own selection, so switching a tool off actually removes it.
#
# `curl` is the exception, and stays: the tool installers (rustup, nix, brew) download
# with it, so the image cannot build without it whatever was selected.
#
# Deliberately no: sudo, docker-cli, podman, nerdctl, sshd, gcc-setuid tools,
# nfs/cifs clients. Nothing in here grants a path out of the container.
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        xz-utils \
        less \
        procps \
        psmisc \
        iproute2 \
        iptables \
        util-linux \
        findutils \
        diffutils \
        patch \
        make \
        socat \
        tini; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Optional compiler toolchain (off by default; keeps the image ~250 MB smaller)
# ---------------------------------------------------------------------------
RUN set -eux; \
    if [ "$INSTALL_BUILD_TOOLS" = "1" ]; then \
        apt-get update; \
        apt-get install -y --no-install-recommends \
            build-essential \
            pkg-config \
            python3 \
            python3-pip \
            python3-venv \
            python3-dev; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# ---------------------------------------------------------------------------
# The unprivileged sandbox user.
#
# The `node` image ships uid/gid 1000 named `node`. We rename it to `deepcode`
# so in-container identity never collides with a host `node` user, then give it
# a home that the entrypoint can populate from the read-only settings mount.
# ---------------------------------------------------------------------------
RUN set -eux; \
    groupmod -n deepcode node; \
    usermod -l deepcode -d /home/deepcode -m -g deepcode -s /bin/bash node; \
    mkdir -p /home/deepcode/.deepcode /home/deepcode/.config /home/deepcode/.cache; \
    chown -R 1000:1000 /home/deepcode; \
    chmod 0755 /home/deepcode

# ---------------------------------------------------------------------------
# Deepsand runtime assets
# ---------------------------------------------------------------------------
COPY bin/ /usr/local/lib/deepsand/
COPY seccomp-hardened.json /usr/local/lib/deepsand/seccomp-hardened.json
RUN set -eux; \
    # Strip CR from these files. A CRLF shebang makes the entrypoint unrunnable
    # inside Linux ("/usr/bin/env: 'bash\r': No such file or directory"), and that
    # failure only appears at container start, never at build time. .gitattributes
    # keeps the sources LF, but a working tree copied in by hand -- or a tarball
    # with the wrong endings -- would reintroduce it, so normalise here and make
    # the image correct regardless of how the source arrived.
    sed -i 's/\r$$//' /usr/local/lib/deepsand/*.sh /usr/local/lib/deepsand/*.mjs; \
    chmod 0755 /usr/local/lib/deepsand/*.sh /usr/local/lib/deepsand/*.mjs; \
    chmod 0644 /usr/local/lib/deepsand/seccomp-hardened.json; \
    ln -sf /usr/local/lib/deepsand/entrypoint.sh /usr/local/bin/deepsand-entrypoint; \
    ln -sf /usr/local/lib/deepsand/deepsand-mcp-bridge.mjs /usr/local/bin/deepsand-mcp-bridge; \
    # Fail the build rather than ship a broken shebang.
    head -n 1 /usr/local/lib/deepsand/entrypoint.sh | grep -qx '#!/usr/bin/env bash'; \
    head -n 1 /usr/local/lib/deepsand/netfilter.sh | grep -qx '#!/usr/bin/env bash'

# ---------------------------------------------------------------------------
# Agent Skills.
#
# DeepCode discovers skills from four roots, in priority order:
#
#   <project>/.deepcode/skills   <project>/.agents/skills
#   ~/.deepcode/skills           ~/.agents/skills
#
# plus a `bundled:` root inside its own package. Skills are directories holding a
# SKILL.md, and they are selected by the model from their name and description
# rather than being always-on text. That makes them the right home for the
# per-task playbook, and it matters for a second reason: `AGENTS.md` has a
# precedence trap. DeepCode loads <project>/AGENTS.md or <project>/.deepcode/
# AGENTS.md if either exists, and only falls back to ~/.deepcode/AGENTS.md when
# the project has neither. Most real repositories ship their own AGENTS.md, so a
# user-level AGENTS.md is silently ignored in exactly the projects that need it
# most. A skill has no such dependency.
#
# Installing at the user level (~/.agents/skills) rather than in the project
# keeps it out of the operator's repository, which must stay untouched.
COPY skills/ /home/deepcode/.agents/skills/
RUN set -eux; \
    # Same CR caveat as the shell scripts: a stray CR inside a frontmatter line
    # or a fence would corrupt the skill body.
    find /home/deepcode/.agents/skills -type f -exec sed -i 's/\r$$//' {} +; \
    chown -R 1000:1000 /home/deepcode/.agents; \
    chmod -R a+rX /home/deepcode/.agents; \
    # Every skill must be a directory containing a readable SKILL.md with a name,
    # or DeepCode will silently skip it.
    for skill in /home/deepcode/.agents/skills/*/; do \
        test -f "$skill/SKILL.md"; \
        grep -q '^name:' "$skill/SKILL.md"; \
        grep -q '^description:' "$skill/SKILL.md"; \
    done

# ---------------------------------------------------------------------------
# Git defaults.
#
# git is installed, but an unconfigured git is barely usable in a sandbox: it
# refuses to touch a bind-mounted repository ("detected dubious ownership") and
# aborts every commit ("Author identity unknown"). Both failures look like the
# project is broken rather than the sandbox being unconfigured, so the settings
# are baked in here. See runtime/gitconfig for the reasoning behind each key.
#
# System level, not global: the sandbox user's home is on the read-only image
# layer, so `git config --global` cannot write to it.
# Scratch space that exists even when no tmpfs is mounted (defensive; Deepsand
# always mounts tmpfs over /tmp and /run when the rootfs is read-only).
# ---------------------------------------------------------------------------
# Tools.
#
# One group per installer, each referencing the argument that governs it. An
# argument that a RUN does not mention does not invalidate its cache layer, so
# `$APT_PACKAGES` has to appear in the command for a changed package list to be
# noticed -- that is why these are separate from the variable declarations above.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Selected tools
#
# One step rather than one per provider. Each provider used to have its own RUN, so a
# build showed the same nine steps whether one tool was selected or all of them: the
# work was conditional, but the log was not. Consolidating makes the log say what
# actually happened.
#
# The arguments live here, immediately before their use, because a changed ARG
# invalidates every instruction after it and nothing above this point depends on them.
# ---------------------------------------------------------------------------
# The C toolchain that `cargo install` needs is removed again once the binaries are
# built, and the Rust toolchain with it unless `cargo` was actually selected. A
# compiler inside the sandbox lowers the effort needed to develop and run local
# exploits, and one default tool (htmlq) was otherwise enough to install one.

ARG INSTALL_TOOLS=""
ARG APT_PACKAGES=""
ARG NPM_GLOBALS=""
ARG CARGO_INSTALLS=""
ARG WITH_NODE_REPO=0
ARG WITH_RUSTUP=0
ARG WITH_GO=0
ARG WITH_BREW=0
ARG WITH_NIX=0

RUN set -eux; \
    if [ -z "$INSTALL_TOOLS" ]; then \
      echo "deepsand: no tools selected for this project"; \
    else \
      echo "deepsand: installing $INSTALL_TOOLS"; \
    fi; \
    if [ "$WITH_NODE_REPO" = "1" ]; then \
      curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -; \
      apt-get install -y --no-install-recommends nodejs; \
      rm -rf /var/lib/apt/lists/*; \
    fi; \
    if [ -n "$APT_PACKAGES" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends $APT_PACKAGES; \
      rm -rf /var/lib/apt/lists/*; \
    fi; \
    if [ "$WITH_GO" = "1" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends golang-go; \
      rm -rf /var/lib/apt/lists/*; \
    fi; \
    if [ -n "$NPM_GLOBALS" ]; then \
      for pkg in $(echo "$NPM_GLOBALS" | tr ',' ' '); do \
        npm install -g --no-fund --no-audit "$pkg@latest"; \
      done; \
    fi; \
    if [ "$WITH_RUSTUP" = "1" ]; then \
      export RUSTUP_HOME=/home/deepcode/.rustup CARGO_HOME=/home/deepcode/.cargo; \
      if ! command -v cargo >/dev/null 2>&1; then \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
          | sh -s -- -y --no-modify-path --profile minimal; \
      fi; \
    fi; \
    if [ -n "$CARGO_INSTALLS" ]; then \
      # A minimal C toolchain. `cargo install` links its output and fails with
      # "linker `cc` not found" without one, and the default tool set includes a
      # cargo-installed program -- so without this the default image could not be
      # built at all unless the operator happened to also want the full build tools.
      apt-get update; \
      apt-get install -y --no-install-recommends gcc libc6-dev; \
      rm -rf /var/lib/apt/lists/*; \
      export RUSTUP_HOME=/home/deepcode/.rustup CARGO_HOME=/home/deepcode/.cargo; \
      export PATH="$CARGO_HOME/bin:$PATH"; \
      if ! command -v cargo >/dev/null 2>&1; then \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
          | sh -s -- -y --no-modify-path --profile minimal; \
      fi; \
      for crate in $(echo "$CARGO_INSTALLS" | tr ',' ' '); do \
        cargo install --locked --root /usr/local "$crate"; \
      done; \
      apt-get purge -y gcc libc6-dev || true; \
      apt-get autoremove -y || true; \
      rm -rf /var/lib/apt/lists/*; \
      case ",$INSTALL_TOOLS," in \
        *,cargo*) echo "deepsand: keeping the Rust toolchain, cargo was selected"; ;; \
        *) rm -rf /home/deepcode/.cargo /home/deepcode/.rustup; ;; \
      esac; \
    fi; \
    if [ "$WITH_BREW" = "1" ]; then \
      export NONINTERACTIVE=1; \
      export HOME=/home/deepcode; \
      mkdir -p /home/deepcode/.linuxbrew; \
      curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash; \
    fi; \
    if [ "$WITH_NIX" = "1" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends xz-utils; \
      rm -rf /var/lib/apt/lists/*; \
      # A downloaded script rather than `sh <(...)`: process substitution is a bash
      # feature, and the Dockerfile's shell is dash, where it is a *parse* error that
      # fails the RUN even when this branch is not taken.
      curl -L https://nixos.org/nix/install -o /tmp/nix-install.sh; \
      sh /tmp/nix-install.sh --no-daemon --yes; \
    fi

# The system git config, applied after the tools so `git` exists when it was selected.
# A project without git still gets the file -- harmless -- but there is nothing to
# verify it against, so the check is skipped rather than failing the build.
COPY gitconfig /etc/gitconfig
RUN set -eux; \
    sed -i 's/\r//g' /etc/gitconfig; \
    chmod 0644 /etc/gitconfig; \
    if command -v git >/dev/null 2>&1; then \
      # Prove git actually reads it, because a config in the wrong place fails
      # silently and produces the very errors this is meant to prevent.
      # `grep -x` matches a whole line, so no anchors (and no `$`, which would have
      # to be escaped for the Dockerfile) are involved.
      git config --system --get safe.directory | grep -qx '[*]'; \
      git config --system --get user.email | grep -qx 'deepcode@deepsand.invalid'; \
      git config --system --get init.defaultBranch | grep -qx 'main'; \
    else \
      echo "deepsand: git was not selected, so the system config is not verified"; \
    fi

# Tool directories have to be on PATH or the tools are installed but unusable: a
# cargo-installed program lands in $CARGO_HOME/bin, which is not on the base image's
# PATH. Listing every home-relative location a provider might use means adding a
# provider later does not silently produce an invisible tool.
ENV PATH="/home/deepcode/.cargo/bin:/home/deepcode/.local/bin:/home/deepcode/.nix-profile/bin:/home/deepcode/.linuxbrew/bin:${PATH}"

# Record what the image was built with, so "which tools does this project have" is
# answerable from the image itself rather than by rebuilding the answer from settings
# that may since have changed.
# ---------------------------------------------------------------------------
# DeepCode CLI
#
# Last, and that placement is the point. $DEEPCODE_REFRESH changes on every build so
# that `@latest` really means latest, and any instruction after it is invalidated with
# it. At the end of the file that costs one layer; anywhere earlier it cost the whole
# image, which is what made every launch rebuild all of the tool steps.
# ---------------------------------------------------------------------------
ARG DEEPCODE_REFRESH=0
RUN set -eux; \
    echo "deepsand: refreshing DeepCode (build $DEEPCODE_REFRESH)"; \
    npm install -g --no-fund --no-audit "@vegamo/deepcode-cli@${DEEPCODE_CLI_VERSION}"; \
    npm cache clean --force; \
    deepcode --version

LABEL deepsand.tools="$INSTALL_TOOLS"
LABEL deepsand.deepcode.refresh="$DEEPCODE_REFRESH"

RUN set -eux; \
    chown -R 1000:1000 /home/deepcode/.cargo /home/deepcode/.rustup /home/deepcode/.linuxbrew /home/deepcode/.nix-profile 2>/dev/null || true

RUN mkdir -p /deepsand/ipc/requests /deepsand/ipc/responses /deepsand/state /workspace

WORKDIR /workspace

# The entrypoint starts as root only long enough to apply the egress policy and
# repair volume ownership, then irreversibly drops to uid 1000 before exec'ing
# DeepCode. See bin/entrypoint.sh.
ENTRYPOINT ["/usr/local/lib/deepsand/entrypoint.sh"]
CMD ["deepcode"]
