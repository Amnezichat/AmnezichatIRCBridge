FROM debian:12

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && \
    apt-get install -y \
        curl \
        build-essential \
        clang \
        cmake \
        libclang-dev \
        llvm-dev \
        net-tools \
        libxkbcommon-x11-0 \
        git \
        tor \
        torsocks \
        pkg-config \
        iputils-ping \
        libglib2.0-dev \
        libssl-dev \
        libgtk-3-dev \
        dnsutils

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN git clone https://github.com/Amnezichat/AmnezichatIRCBridge.git /opt/AmnezichatIRCBridge

WORKDIR /opt/AmnezichatIRCBridge/bridge
RUN cargo build --release

CMD bash -c "\
    if ! pgrep -x tor > /dev/null; then \
        echo 'Starting Tor service...'; \
        tor & \
        sleep 5; \
    else \
        echo 'Tor is already running...'; \
    fi; \
    torsocks cargo run --release"
