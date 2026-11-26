# Uninstalling goop-steppa

Do the steps in order. **Step 1 matters most**: if your system resolver still points at goop-steppa
when it stops, name resolution on the machine fails. Every step is safe to run even if you never
did the matching install step (they are all no-ops then).

## 1. Restore your system DNS

If you ran `goop-steppa setup --apply`, undo it:

```sh
sudo goop-steppa setup --revert
```

No goop-steppa binary any more, or it is broken? Do the same by hand:

```sh
sudo rm -f /etc/systemd/resolved.conf.d/goop-steppa.conf
sudo systemctl restart systemd-resolved
```

If you used Option B (manual), undo what you changed: e.g. in NetworkManager set the connection's DNS
back to automatic, and remove any `setcap` grant (step 3).

Check that DNS works before continuing: `resolvectl query example.com` (or `dig example.com`).

## 2. Stop and remove the service

If you set up the user service:

```sh
systemctl --user disable --now goop-steppa 2>/dev/null
rm -f ~/.config/systemd/user/goop-steppa.service
systemctl --user daemon-reload
sudo loginctl disable-linger "$USER"   # only if you enabled lingering just for this
```

If you ran it by hand, stop it: `pkill -x goop-steppa`.

## 3. Remove the binary

```sh
cargo uninstall goop-steppa            # if installed with `cargo install`
```

Built in place instead? Just delete the cloned `goop-steppa/` directory (this also removes `target/`).

If you gave it the port-53 capability, it went away with the binary. To clear it from a binary you
are keeping: `sudo setcap -r "$(command -v goop-steppa)"`.

## 4. Delete your data (optional)

This permanently deletes your query history, downloaded lists, and your own block/allow lists.
Back up `blocklist.txt` and `allowlist.txt` first if you want to keep them.

```sh
rm -rf ~/.config/goop-steppa ~/.local/share/goop-steppa
```

## One-shot script

All of the above, in one go (keeps your data unless you add `--purge`):

```sh
#!/usr/bin/env bash
set -u
purge="${1:-}"

# 1. restore DNS
if command -v goop-steppa >/dev/null; then sudo goop-steppa setup --revert || true; fi
sudo rm -f /etc/systemd/resolved.conf.d/goop-steppa.conf
sudo systemctl restart systemd-resolved 2>/dev/null || true

# 2. service / process
systemctl --user disable --now goop-steppa 2>/dev/null || true
rm -f ~/.config/systemd/user/goop-steppa.service
systemctl --user daemon-reload 2>/dev/null || true
pkill -x goop-steppa 2>/dev/null || true

# 3. binary
cargo uninstall goop-steppa 2>/dev/null || true

# 4. data
if [ "$purge" = "--purge" ]; then rm -rf ~/.config/goop-steppa ~/.local/share/goop-steppa; fi

echo "Done. Verify DNS: resolvectl query example.com"
```

## Verify

```sh
ls /etc/systemd/resolved.conf.d/goop-steppa.conf   # should say: No such file
command -v goop-steppa                             # should print nothing
resolvectl status | grep -i 'DNS Servers'          # should not list 127.0.0.1
```
