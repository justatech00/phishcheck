# Sample emails for phishcheck

All of these emails are fake. The companies are made up (Northwind Bank,
Contoso, Fabrikam), the domains use the reserved `.example` and `.test`
endings, and the IP addresses come from documentation-only ranges
(192.0.2.x, 198.51.100.x, 203.0.113.x). None of them point anywhere real.
The attachments are harmless placeholder text.

Brand list for the lookalike check (stage 12): `northwindbank.example`,
`contoso.example`, `fabrikam.example`.

## Answer key: what each file should trigger

| file | expected verdict | what it tests |
|---|---|---|
| `01-legit.eml` | clean | The baseline. Every check should pass: spf/dkim/dmarc pass, sender domains match, links match their text. Multipart (text + html). **CRLF line endings.** |
| `02-reply-to-mismatch.eml` | likely phishing | Reply-To on a free-mail domain, Return-Path on a different domain from From, spf softfail, dmarc fail, urgency and threats, asks for a password and a 2FA code. Plain text only. |
| `03-auth-fail.eml` | likely phishing | spf fail, dkim none, dmarc fail. The Received chain claims `mail.northwindbank.example` but the real host is `vps-2291.cheap-hosting.test`. Asks for card number and PIN. Note that the From address looks perfectly legitimate. |
| `04-link-tricks.eml` | likely phishing | Display name "Northwind Bank" on an unrelated domain. Body is **base64-encoded HTML** with **CRLF line endings**. Link text differs from href, IP address URL, plain http, URL shortener, `@` in a URL, punycode domain, very deep subdomain. One link (help centre) is legitimate, as a control. |
| `05-lookalike.eml` | likely phishing | Lookalike domains: `northwlndbank` (i to l), `northvvindbank` (w to vv), `c0ntoso` (o to 0), `contos0`. Link text shows `contoso.example` but points elsewhere. **Encoded words** in From and Subject. **Quoted-printable** body with soft line breaks (`=` at the end of a line) and `=3D`. All auth checks pass, because the attacker owns the lookalike domain. |
| `06-attachment.eml` | likely phishing | Invoice / bank-details-change scam (business email compromise). Risky attachments `.html` and `.zip`. dkim fail, dmarc fail, Reply-To on a free-mail domain. Payment pressure and secrecy ("keep this confidential"). multipart/mixed. |

## Things that will trip up a naive parser
- `01` and `04` use Windows-style `CRLF` line endings, and the others use `LF`.
  Your code must handle both.
- `Received` and `Authentication-Results` are **folded** across several
  lines (continuation lines start with a tab).
- `Received` appears more than once in the same email.
