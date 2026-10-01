# phishcheck: a phishing email analyzer

`phishcheck` is a PowerShell tool that checks a saved email (`.eml` file)
for signs of phishing. It reads the email's headers, checks who really
sent it, and gives a verdict:

- **CLEAN**
- **SUSPICIOUS**
- **LIKELY PHISHING**

The verdict comes with the reasons behind it.

It works **fully offline**. It never opens links, never downloads
anything, and never opens attachments. It only reads the text of the
`.eml` file.

This is a learning project, built stage by stage to learn PowerShell.

## Requirements

- PowerShell 7 (`pwsh`). It is installed by default on Parrot OS.
  The script also works on Windows.
- No extra modules.

## How to save an email as `.eml`

| mail app | how |
|---|---|
| Gmail (web) | open the email, ⋮ menu, **Download message** |
| Outlook (web) | open the email, ⋯ menu, **Download** |
| Thunderbird | open the email, **File > Save As** |

## Usage

```bash
./phishcheck.ps1 <file.eml>                # analyse one email
./phishcheck.ps1 <file.eml> -ShowHeaders   # also show every header and address
Get-Help ./phishcheck.ps1 -Full            # built-in help (run inside pwsh)
```

If `./phishcheck.ps1` says "permission denied", run `chmod +x phishcheck.ps1`
once. You can also run it as `pwsh ./phishcheck.ps1 <file.eml>`.

### Example

```
$ ./phishcheck.ps1 samples/02-reply-to-mismatch.eml
phishcheck: samples/02-reply-to-mismatch.eml
From:     "Northwind Bank Security" <security@northwindbank.example>
Subject:  URGENT: Unusual sign-in detected on your account
Auth:     SPF softfail | DKIM none | DMARC fail

VERDICT: LIKELY PHISHING (score 70/100)

Reasons:
  [High  ] Auth: DMARC result: fail
  [Medium] Sender: Reply-To domain (freemail-inbox.test) differs from From domain (northwindbank.example)
  [Medium] Auth: SPF result: softfail
  [Low   ] Sender: Return-Path domain (bulkmail-relay.test) differs from From domain (northwindbank.example)
  [Low   ] Auth: DKIM result: none
```

### Exit codes

Other scripts can use the exit code to act on the verdict.

| code | meaning |
|---|---|
| 0 | clean |
| 1 | suspicious |
| 2 | likely phishing |
| 3 | error (for example, the file was not found) |

## What it checks

### Sender checks

| check | severity |
|---|---|
| Reply-To is on a different domain from From | Medium |
| Return-Path is on a different domain from From | Low |
| The display name uses a known brand, but the address is not on that brand's domain | High |
| The display name contains an email address that is not the real one | High |

### Authentication checks

These come from the `Authentication-Results` header, which the receiving
mail server adds.

| result | severity |
|---|---|
| SPF fail, DMARC fail | High |
| DKIM fail, SPF softfail | Medium |
| none, neutral, missing, or any error | Low |
| pass | no finding |

### Scoring

Each finding adds points:

- High: **30** points
- Medium: **15** points
- Low: **5** points

The score is capped at 100.

| score | verdict |
|---|---|
| 0–19 | CLEAN |
| 20–49 | SUSPICIOUS |
| 50 or more | LIKELY PHISHING |

The known brands and their real domains are set in the `$brands` list in
the script. Edit it to add your own.

## Results on the sample emails

The `samples/` folder has six fake test emails. `samples/README.md` explains
what each one tests.

| sample | verdict | score |
|---|---|---|
| 01-legit | CLEAN | 0 |
| 02-reply-to-mismatch | LIKELY PHISHING | 70 |
| 03-auth-fail | LIKELY PHISHING | 65 |
| 04-link-tricks | SUSPICIOUS | 35 |
| 05-lookalike | CLEAN ⚠️ missed | 0 |
| 06-attachment | LIKELY PHISHING | 60 |

## Limitations

phishcheck only reads the **headers** for now:

- **Not checked yet:** the body, links and attachments. Sample 04 only
  scores SUSPICIOUS, because its bad links are not checked.
- **Not detected yet:** lookalike domains such as `northwlndbank` (i to l).
  Sample 05 passes as CLEAN, because the attacker owns that domain, so
  SPF, DKIM and DMARC all pass.
- **Not decoded yet:** encoded names and subjects (`=?UTF-8?B?...?=`).
  They are shown as they are.
- **Not checked yet:** the chain of `Received` servers.

A CLEAN verdict means "no warning signs found by these checks". It does not
mean the email is safe.

## Possible next stages

These stages from the original plan were skipped:

- **7:** trace the `Received` chain
- **8–11:** read MIME parts, decode the body, extract and check links
- **12:** detect lookalike domains (catches sample 05)
- **13:** content red flags (urgent wording, risky attachments)
- **16–18:** JSON and Markdown reports, scanning a whole folder, decoding
  encoded names and subjects
