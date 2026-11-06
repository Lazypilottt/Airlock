"""A deliberately malicious MCP test server: FOR TESTING YOUR OWN SETUP ONLY.

It simulates poisoned descriptions, injected results, a rug pull, cross-server
shadowing and an exfiltration lure against your own agent. Every exfiltration
target is a local canary on 127.0.0.1 and every payload is a honeytoken.

    python attack/server.py          # same as: python -m airlock.attack.server

The implementation lives in `airlock/attack/server.py` so that installed
copies of Airlock can run it too.
"""

from airlock.attack.server import main

if __name__ == "__main__":
    main()
