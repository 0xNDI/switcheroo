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
uv run switcheroo git+https://github.com/0xNDI/switcheroo
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
    -rbcd 'ATTACKER_MACHINE$'
```

`-rbcd` takes the account you want the RBCD descriptor to grant (its `objectSid` is
looked up over LDAP) or a raw `S-1-5-...` SID — both verified at startup, before any
coercion.

`-base-dn` is optional: the search base comes from the DC's `rootDSE
defaultNamingContext`. The modify target defaults to the relayed victim's own object, so both
`-modify-dn` and `-modify-sam` are optional. `-listen-ip` defaults to `0.0.0.0`, i.e. all
interfaces. Pass any of them to override, e.g. to write onto an object other than the
coerced host — by DN or by `sAMAccountName` (resolved over LDAP):

```
sudo switcheroo \
    'DOMAIN/attacker[:password]@DC.fqdn' \
    -dc-ip <DC_IP> \
    -listen-ip <ATTACKER_IP> \
    -victim 'DOMAIN/VICTIM$' \
    -modify-sam 'VICTIM$' \
    -rbcd 'ATTACKER_MACHINE$'
```

Then coerce the victim toward one of your addresses from another terminal.

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
| `-dc-ip` / `-listen-ip` | DC IP, attacker listener IP (default: `0.0.0.0`) |
| `-base-dn` | search base (default: the DC's `defaultNamingContext`) |
| `-victim DOMAIN/account` | only relay this victim |
| `-modify-dn DN` / `-modify-sam ACCOUNT` | object to modify as the victim, by DN or by sAMAccountName (default: the victim's own account) |
| `-rbcd ACCOUNT\|SID` | write an RBCD descriptor granting this account (sAMAccountName, SID resolved via LDAP) or raw SID |
| `-value` / `-value-hex` / `-attribute` | write an arbitrary attribute instead of RBCD |
| `-ntlmrelayx PATH` | optional: run a specific `ntlmrelayx.py` instead of the installed one |
| `-use-kerberos` / `-k` | Kerberos for the attacker's signed LDAP connections (TGT from password/hashes) instead of NTLM; the relayed victim auth is unaffected |
| `-hashes`, `-no-pass`, `-debug`, `-ts` | auth / logging |

The tool prints the DC's `Bind`/`Modify` result codes and does an independent signed
read-back to confirm the write (the SMB/coercion side may still print `FAILED`).
