# Install

AVHSOL installs for your user only: no sudo, and nothing is added to your shell files.

```
scripts/install.sh                  # or: make install
scripts/install.sh --prefix DIR     # install somewhere else
scripts/install.sh --with-harness   # also copy the pi harness (needs Node; only for simulated-tool scenarios and `hunt`)
scripts/install.sh --uninstall      # remove it (--purge also deletes your runs and keys)
```

Needs Go 1.22+ and a Rust toolchain to build. The script puts three programs in `~/.local/bin` (`avhsol`, `avhsol-proxy`,
`avhsol-sandbox`) and the scenarios, seeds and target templates in `~/.local/share/avhsol`. Your trace-signing key goes to
`~/.config/avhsol/signing.key` (created on first install, mode 600) and runs and the threat-intel cache to
`~/.local/share/avhsol`. If `~/.local/bin` is not on your `PATH` the script says so and prints the line to add.

## Where things are looked up

`internal/home` decides, so the same binary works from a checkout and from an install:

| What | Order |
|---|---|
| assets (`scenarios/ seeds/ targets/`) | `$AVHSOL_HOME`, `<prefix>/share/avhsol` next to the binary, the repository checkout, `~/.local/share/avhsol` |
| helper binaries | next to `avhsol`, the checkout's `guard/target/release`, then `PATH` |
| signing key, `stack.env` | `$AVHSOL_CONFIG`, `deploy/stack` in a checkout, else `~/.config/avhsol` |
| runs, intel cache | `$AVHSOL_STATE`, the checkout, else `~/.local/share/avhsol` |

A relative path such as `-scenario scenarios/devops-coder.yaml` that does not exist in your current directory is looked up
in the assets directory, so the examples in these docs work from anywhere.

## Use it

```
cd /path/to/your/agent && avhsol .      # see WHITEBOX.md
avhsol                                  # the menu
claude mcp add avhsol -- avhsol mcp     # see MCP.md
```

The model for the attack step is configured only by environment variables: `AVHSOL_LLM_BASE_URL`, `AVHSOL_LLM_MODEL`,
`AVHSOL_LLM_API_KEY`.
