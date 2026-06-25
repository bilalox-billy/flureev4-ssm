"""
run_tutorial.py — Interactive Fluree Auth Tutorial Runner
==========================================================

This is the main entry point for the tutorial.

Run it with:
    python -m src.run_tutorial

or:
    python src/run_tutorial.py

You will be asked to choose between:
  [A] OIDC authentication  (browser-based login via Google, Cognito, Okta, etc.)
  [B] Manual Bearer token  (paste a token directly)

After authentication, a set of demo queries will run to show you how
to interact with your Fluree ledger using Python.

PREREQUISITES
─────────────
  1. Copy .env.example → .env
  2. Fill in at minimum:
       FLUREE_BASE_URL=https://your-fluree-server.example.com
       FLUREE_LEDGER=your-org/your-ledger

  For Mode A (OIDC), also fill in:
       OIDC_ISSUER, OIDC_CLIENT_ID, FLUREE_EXCHANGE_URL

  For Mode B (manual), also fill in:
       FLUREE_BEARER_TOKEN=eyJ...
"""

import sys
from pathlib import Path

# Ensure the project root is on sys.path so `import src.*` works whether
# this file is run as  `python src/run_tutorial.py`  or
# as a module         `python -m src.run_tutorial`.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ── Colour helpers ────────────────────────────────────────────────────────────
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _print_welcome() -> None:
    width = 62
    print()
    print(f"{_BOLD}{_CYAN}{'╔' + '═' * (width - 2) + '╗'}{_RESET}")
    print(f"{_BOLD}{_CYAN}║{'Fluree v4 — Python Auth Tutorial':^{width - 2}}║{_RESET}")
    print(f"{_BOLD}{_CYAN}║{'Hosted on AWS':^{width - 2}}║{_RESET}")
    print(f"{_BOLD}{_CYAN}{'╚' + '═' * (width - 2) + '╝'}{_RESET}")
    print()
    print("  This tutorial demonstrates two ways to authenticate with")
    print("  a Fluree database server running on AWS, then runs live")
    print("  example queries against your configured ledger.")
    print()
    print(f"  {_BOLD}Reference:{_RESET} https://labs.flur.ee/docs/db/design/auth-contract")
    print()


def _print_mode_menu() -> None:
    width = 58
    print(f"  {_BOLD}{'─' * width}{_RESET}")
    print(f"  {_BOLD}  Choose your authentication mode:{_RESET}")
    print(f"  {_BOLD}{'─' * width}{_RESET}")
    print()
    print(f"  {_BOLD}[A]{_RESET}  {_GREEN}Mode A — OIDC (browser-based login){_RESET}")
    print(f"       Your identity provider (Google, Cognito, Okta, etc.)")
    print(f"       opens in a browser. No token needed upfront.")
    print(f"       Best for: interactive sessions, real users.")
    print()
    print(f"  {_BOLD}[B]{_RESET}  {_CYAN}Mode B — Manual Bearer Token{_RESET}")
    print(f"       Paste a token you already have (from your admin,")
    print(f"       the CLI, or a previous auth flow).")
    print(f"       Best for: automation, CI/CD, service accounts.")
    print()
    print(f"  {_BOLD}[Q]{_RESET}  Quit")
    print()
    print(f"  {_BOLD}{'─' * width}{_RESET}")


def _check_env_file() -> None:
    """Warn the user if the .env file is missing."""
    from pathlib import Path
    env_path = Path(__file__).resolve().parent.parent / ".env"
    example_path = env_path.parent / ".env.example"

    if not env_path.exists():
        print(f"  {_YELLOW}{_BOLD}⚠  WARNING: .env file not found at:{_RESET}")
        print(f"     {env_path}")
        print()
        if example_path.exists():
            print(f"  {_CYAN}→{_RESET}  Copy the example file and fill in your values:")
            print(f"     copy .env.example .env")
        else:
            print(f"  {_CYAN}→{_RESET}  Create a .env file with at minimum:")
            print(f"     FLUREE_BASE_URL=https://your-fluree-server.example.com")
            print(f"     FLUREE_LEDGER=your-org/your-ledger")
        print()


def _pick_mode() -> str:
    """Prompt the user to choose a mode and return 'A' or 'B'."""
    while True:
        try:
            choice = input("  Your choice [A/B/Q]: ").strip().upper()
        except (KeyboardInterrupt, EOFError):
            print()
            print(f"\n  {_YELLOW}Bye!{_RESET}")
            sys.exit(0)

        if choice in ("A", "B", "Q"):
            return choice
        print(f"  {_RED}Invalid choice — please enter A, B, or Q.{_RESET}")


def main() -> None:
    """Main tutorial runner."""
    _print_welcome()
    _check_env_file()
    _print_mode_menu()

    mode = _pick_mode()
    print()

    if mode == "Q":
        print(f"  {_YELLOW}Bye!{_RESET}")
        return

    if mode == "A":
        # ── Mode A: OIDC ─────────────────────────────────────────────────
        from src.auth_mode_a_oidc import run_mode_a, demo_queries
        client = run_mode_a()
        print()
        print(f"  {_BOLD}Run demo queries now?{_RESET}")
        if input("  [y/N]: ").strip().lower() == "y":
            demo_queries(client)

    elif mode == "B":
        # ── Mode B: Manual Token ──────────────────────────────────────────
        from src.auth_mode_b_token import run_mode_b, demo_queries
        client = run_mode_b()
        print()
        print(f"  {_BOLD}Run demo queries now?{_RESET}")
        if input("  [y/N]: ").strip().lower() == "y":
            demo_queries(client)

    print()
    print(f"  {_GREEN}{_BOLD}Tutorial complete!{_RESET}")
    print()
    print("  You now have an authenticated FlureeClient. Here's how")
    print("  to use it in your own code:")
    print()
    print(f"  {_CYAN}  from src.fluree_client import FlureeClient{_RESET}")
    print()
    print(f"  {_CYAN}  client = FlureeClient({_RESET}")
    print(f"  {_CYAN}      base_url='https://your-server.example.com',{_RESET}")
    print(f"  {_CYAN}      token='eyJ...',{_RESET}")
    print(f"  {_CYAN}      ledger='your-org/your-ledger',{_RESET}")
    print(f"  {_CYAN}  ){_RESET}")
    print()
    print(f"  {_CYAN}  rows = client.query('SELECT ?s ?p ?o WHERE {{?s ?p ?o}} LIMIT 10'){_RESET}")
    print(f"  {_CYAN}  client.insert([{{'@id': 'ex:node1', 'ex:name': 'Hello'}}]){_RESET}")
    print(f"  {_CYAN}  client.print_whoami(){_RESET}")
    print()
    print(f"  {'─' * 58}")
    print(f"  Docs: https://labs.flur.ee/docs/db/")
    print()


if __name__ == "__main__":
    main()
