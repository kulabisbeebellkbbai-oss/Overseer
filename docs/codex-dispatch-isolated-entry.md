# Codex dispatch isolated entry

Codex dispatch activation has a distinct startup trust boundary. The service
and the activation-only CLI must execute `src/overseer_codex_dispatch_launcher.py`
directly with a fixed Python interpreter and both `-I` and `-S`. Calling
`python -m overseer.cli` is not an authorized way to stage or execute this
activation kind.

The launcher is stdlib-only until it has verified the canonical checkout's
exact Git commit and tree, clean tracked state, executable `.py`/`.pyc`
inventory, module digest, review digest, and activation-spec digest. It rejects
untracked executable Python, including `sitecustomize.py`, `usercustomize.py`,
and sourceless bytecode. Paired PEP 3147 cache files are non-authoritative and
the launcher installs a source/extension-only import hook, so bytecode files
cannot be imported after validation.

After validation, the launcher explicitly adds only the reviewed `src`
directory and the fixed Overseer virtual environment's `site-packages`. Its
typed modes permit the exact `serve-api` command or the three Codex dispatch
activation CLI commands. The normal CLI rejects activation staging and
execution unless the isolated launcher established the binding.

The approved systemd drop-in clears `PYTHONPATH`, clears the inherited
`ExecStart`, and installs the exact isolated service command with the reviewed
store, loopback host, port, and API-token-file arguments. The drop-in remains
approval-gated and is not installed merely by building or testing this source.
