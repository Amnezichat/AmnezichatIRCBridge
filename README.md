# Amnezichat-IRC Bridge

<img src="banner.png" width="1200">

> ## ⚠️ **Warning:** Using a bridge with Amnezichat is strongly discouraged for privacy reasons. Use it at your own risk.

<!-- INSTALLATION -->
## Bridge setup:

    sudo apt update
    sudo apt install curl build-essential git tor torsocks
    sudo systemctl enable --now tor.service
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    git clone https://github.com/Amnezichat/AmnezichatIRCBridge.git
    cd AmnezichatIRCBridge/bridge/
    cargo build --release
    torsocks cargo run --release

## Bridge setup with Docker:

    sudo apt update
    sudo apt install docker.io git
    git clone https://github.com/Amnezichat/AmnezichatIRCBridge.git
    cd AmnezichatIRCBridge/bridge/
    docker build --network=host -t amnezichatbridge .
    docker run -d --name amnezichatbridge amnezichatbridge


## Requirements:

- [Rust](https://www.rust-lang.org), [Tor](https://gitlab.torproject.org/tpo/core/tor)

<!-- LICENSE -->
## License

Distributed under the GPLv3 License. See `LICENSE` for more information.

## Donate to support development of this project!

**Monero(XMR):** 88a68f2oEPdiHiPTmCc3ap5CmXsPc33kXJoWVCZMPTgWFoAhhuicJLufdF1zcbaXhrL3sXaXcyjaTaTtcG1CskB4Jc9yyLV

**Bitcoin(BTC):** bc1qn42pv68l6erl7vsh3ay00z8j0qvg3jrg2fnqv9
