# Lateral Movement — Notes

## What it is

Once one working credential is in hand — cracked from a captured hash,
relayed live, or hit via spraying — the next step is turning that single
foothold into access across the domain. Lateral movement means using a
credential, hash, or ticket that's valid on one host to authenticate to
*another* host, repeating until something yields domain admin or a path to
the DC.

The credential doesn't need to be a plaintext password. NTLM hashes and
Kerberos tickets are both directly usable for authentication, which is what
makes hash- and ticket-reuse techniques effective — nothing needs to be
cracked, only replayed.

## Common techniques

- **Pass-the-Hash (PtH)** — NTLM authentication only requires the NT hash,
  not the plaintext password, so a hash obtained from memory, SAM, or NTDS
  can authenticate to other hosts directly.
- **Over Pass-the-Hash** — using an NT hash to request a Kerberos ticket
  (rather than authenticating over NTLM), so the session rides Kerberos
  instead.
- **Pass-the-Ticket (PtT)** — reusing a captured or forged Kerberos ticket
  (TGT or service ticket) on another session without ever touching a
  password or hash.
- **Remote execution via WMI/WinRM/SMB** — once a credential or token is
  valid on a target, standard Windows remote-management protocols (WMI,
  WinRM/PowerShell Remoting, SMB-based service execution) run commands on
  that host the same way an admin's own tooling would.

Tooling in this space (Impacket's remote-execution modules, NetExec,
Mimikatz/Rubeus for ticket handling, CrackMapExec-style hash reuse) is the
same across each technique: the difference is *what* gets replayed —
password, NT hash, or Kerberos ticket — not how the resulting session is used.

## Why it matters in the chain

This is the step that turns "one compromised account" into "the domain."
Enumeration (see [AD Enumeration](./ad-enumeration.md)) tells you which hosts
a credential has rights on; lateral movement is actually using those rights
to reach them, usually hunting for a host where a privileged account —
a domain admin, a service account, a helpdesk account with local admin
everywhere — has a live session or cached credential that can be captured
and moved again.

## Detection

- **Pass-the-hash / anomalous NTLM** — an account authenticating via NTLM to
  a host it has never logged into, especially without a corresponding
  interactive logon (Event ID 4624, Logon Type 3) from its usual source host.
- **Pass-the-ticket** — Kerberos tickets presented with inconsistent or
  impossible metadata (e.g. a ticket's originating host/IP not matching the
  presenting host), or Event ID 4769 (service ticket request) volume spikes
  across many hosts in a short window from one account.
- **Remote execution** — new service creation (Event ID 7045), WMI process
  creation (Event ID 4688 with a WMI-launched parent), or WinRM sessions
  (Event ID 4624, Logon Type 3/10) from accounts or hosts that don't normally
  perform remote administration.

## Mitigations

- **LAPS (Local Administrator Password Solution)** — randomize and rotate
  local admin passwords per host so a single local admin hash isn't valid
  everywhere.
- **Restrict NTLM** where possible (prefer Kerberos, disable NTLMv1, audit
  and eventually block NTLM outright via GPO) — removes the easiest
  pass-the-hash path.
- **Credential Guard** to keep NT hashes and Kerberos tickets out of
  reachable process memory (LSASS) in the first place.
- **Tiered administration model** — domain admins never log on to lower-tier
  (workstation-level) hosts, so even a fully compromised workstation can't
  harvest a DA credential to replay.
- **Privileged Access Workstations (PAWs)** for any admin-level logon,
  isolating where high-value credentials ever get cached.
- **Monitor and alert** on the detection signals above, aggregated across
  hosts rather than per-host, since lateral movement is defined by the same
  account touching many hosts in quick succession.

## Lab walkthrough

Not yet run end-to-end in the lab — see [CLAUDE.md](./CLAUDE.md) for the
concept/walkthrough pairing convention this repo follows. A
`lateral-movement-lab-walkthrough.md` page will pair with this one once that
run is captured, with the README's Contents list, flowchart, and ATT&CK table
updated to match.
