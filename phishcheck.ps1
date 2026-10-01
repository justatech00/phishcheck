#!/usr/bin/env -S pwsh -NoProfile

<#
.SYNOPSIS
    phishcheck: analyse a saved email (.eml) for signs of phishing.

.DESCRIPTION
    Reads a .eml file, checks the sender addresses and the SPF/DKIM/DMARC
    results, and gives a verdict: CLEAN, SUSPICIOUS or LIKELY PHISHING.
    Works fully offline. It never opens links or attachments.

    Exit codes: 0 = clean, 1 = suspicious, 2 = likely phishing, 3 = error.

.PARAMETER Path
    The .eml file to analyse.

.PARAMETER ShowHeaders
    Also print every parsed header and the address breakdown.

.EXAMPLE
    ./phishcheck.ps1 ./samples/02-reply-to-mismatch.eml

.EXAMPLE
    ./phishcheck.ps1 ./samples/01-legit.eml -ShowHeaders
#>

param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [switch]$ShowHeaders
)

# ---------- Stage 1: read the file, split headers from body ----------

# Stop with an error if the file doesn't exist
if (-not (Test-Path -Path $Path -PathType Leaf)) {
    Write-Host "File not found: $Path" -ForegroundColor Red
    exit 3
}

# Read the whole file as one string
$text = Get-Content -Path $Path -Raw

# Split at the first blank line (LF or CRLF), into at most 2 pieces
$parts = $text -split '\r?\n\r?\n', 2
$headerText = $parts[0]
$bodyText = $parts[1]

# Header text as an array of lines
$headerLines = $headerText -split '\r?\n'

# ---------- Stage 2: unfold headers ----------

# A line starting with a space or tab continues the previous header.
# Join each such line onto the previous one, so every header is one line.
$headers = @()
foreach ($line in $headerLines) {
    if ($line -match '^[ \t]' -and $headers.Count -gt 0) {
        $headers[-1] += " " + $line.Trim()
    } else {
        $headers += $line
    }
}

# ---------- Stage 3: parse headers into name/value objects ----------

# Turn each "Name: value" line into an object with Name and Value.
# Repeated headers (like Received) are all kept, in their original order.
$parsedHeaders = @()
foreach ($h in $headers) {
    if ($h -match '^([^:\s]+):\s*(.*)$') {
        $parsedHeaders += [PSCustomObject]@{
            Name  = $Matches[1]
            Value = $Matches[2]
        }
    }
}

# Look up a header by name (case-insensitive).
# Returns the first value, or every value with -All. Returns $null if missing.
function Get-Header {
    param(
        [string]$Name,
        [switch]$All
    )
    $found = $parsedHeaders | Where-Object { $_.Name -eq $Name }
    if ($null -eq $found) {
        return $null
    }
    if ($All) {
        return $found.Value
    }
    return @($found)[0].Value
}

# ---------- Stage 4: addresses and domains ----------

# Split an address header value into DisplayName, Address and Domain.
# Handles:  "Name" <a@b.c>   Name <a@b.c>   <a@b.c>   a@b.c
# Returns $null if the value is missing or has no address in it.
function Get-AddressInfo {
    param(
        [string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    if ($Value -match '^(.*)<([^>]+)>') {
        # Form with angle brackets: display name (maybe empty) + <address>
        $displayName = $Matches[1].Trim().Trim('"')
        $address = $Matches[2].Trim()
    } elseif ($Value -match '([^\s<>"]+@[^\s<>"]+)') {
        # Bare address with no display name
        $displayName = ""
        $address = $Matches[1]
    } else {
        return $null
    }

    $domain = $null
    if ($address -match '@([^@]+)$') {
        $domain = $Matches[1].ToLower()
    }

    return [PSCustomObject]@{
        DisplayName = $displayName
        Address     = $address
        Domain      = $domain
    }
}

$fromInfo = Get-AddressInfo (Get-Header 'From')
$replyToInfo = Get-AddressInfo (Get-Header 'Reply-To')
$returnPathInfo = Get-AddressInfo (Get-Header 'Return-Path')

# ---------- Stage 5: sender mismatch checks ----------

# Known brands and their real domains (a config file replaces this in stage 20)
$brands = [ordered]@{
    "Northwind Bank" = "northwindbank.example"
    "Contoso"        = "contoso.example"
    "Fabrikam"       = "fabrikam.example"
}

# Every check adds its findings here. Scoring (stage 14) uses this list.
$findings = @()

# Add one finding to the list
function Add-Finding {
    param(
        [string]$Check,
        [ValidateSet("High", "Medium", "Low")]
        [string]$Severity,
        [string]$Message
    )
    $script:findings += [PSCustomObject]@{
        Check    = $Check
        Severity = $Severity
        Message  = $Message
    }
}

# True if two domains belong to the same organisation:
# equal, or one is a subdomain of the other (mail.x.com and x.com)
function Test-SameDomain {
    param(
        [string]$A,
        [string]$B
    )
    if ([string]::IsNullOrEmpty($A) -or [string]::IsNullOrEmpty($B)) {
        return $false
    }
    return ($A -eq $B) -or $A.EndsWith(".$B") -or $B.EndsWith(".$A")
}

if ($null -ne $fromInfo) {
    # 5a: Reply-To on a different domain means replies go somewhere else
    if ($null -ne $replyToInfo -and -not (Test-SameDomain $replyToInfo.Domain $fromInfo.Domain)) {
        Add-Finding -Check "Sender" -Severity "Medium" `
            -Message "Reply-To domain ($($replyToInfo.Domain)) differs from From domain ($($fromInfo.Domain))"
    }

    # 5b: Return-Path on a different domain (common for mailing services too, so Low)
    if ($null -ne $returnPathInfo -and -not (Test-SameDomain $returnPathInfo.Domain $fromInfo.Domain)) {
        Add-Finding -Check "Sender" -Severity "Low" `
            -Message "Return-Path domain ($($returnPathInfo.Domain)) differs from From domain ($($fromInfo.Domain))"
    }

    # 5c: display name uses a brand, but the address is not on that brand's domain
    foreach ($brand in $brands.Keys) {
        $brandDomain = $brands[$brand]
        if ($fromInfo.DisplayName -like "*$brand*" -and -not (Test-SameDomain $fromInfo.Domain $brandDomain)) {
            Add-Finding -Check "Sender" -Severity "High" `
                -Message "Display name says '$brand' but the address is on $($fromInfo.Domain), not $brandDomain"
        }
    }

    # 5d: display name contains an email address that is not the real address
    if ($fromInfo.DisplayName -match '([^\s<>"]+@[^\s<>"]+)' -and $Matches[1] -ne $fromInfo.Address) {
        Add-Finding -Check "Sender" -Severity "High" `
            -Message "Display name shows address $($Matches[1]) but the real address is $($fromInfo.Address)"
    }
} else {
    Add-Finding -Check "Sender" -Severity "Medium" -Message "No valid From address"
}

# ---------- Stage 6: authentication results (SPF, DKIM, DMARC) ----------

# The receiving mail server records its SPF/DKIM/DMARC verdicts in the
# Authentication-Results header. The first one is from the server closest
# to the recipient, which is the one we trust.
$authHeader = Get-Header 'Authentication-Results'
$auth = [ordered]@{
    spf   = "missing"
    dkim  = "missing"
    dmarc = "missing"
}

if ($null -eq $authHeader) {
    Add-Finding -Check "Auth" -Severity "Low" -Message "No Authentication-Results header"
} else {
    # Read each result, e.g. "spf=softfail" -> softfail
    foreach ($mech in @($auth.Keys)) {
        if ($authHeader -match "\b$mech=(\w+)") {
            $auth[$mech] = $Matches[1].ToLower()
        }
    }

    # Turn each result into a finding (pass = no finding)
    foreach ($mech in $auth.Keys) {
        $result = $auth[$mech]
        $severity = switch ($result) {
            "pass"     { $null }
            "fail"     { if ($mech -eq "dkim") { "Medium" } else { "High" } }
            "softfail" { "Medium" }
            default    { "Low" }    # none, neutral, temperror, permerror, missing
        }
        if ($null -ne $severity) {
            Add-Finding -Check "Auth" -Severity $severity -Message "$($mech.ToUpper()) result: $result"
        }
    }
}

# ---------- Stage 14: scoring and verdict ----------

# Points per finding, and the score needed for each verdict
$weights = @{ High = 30; Medium = 15; Low = 5 }
$suspiciousAt = 20
$phishingAt = 50

$score = 0
foreach ($f in $findings) {
    $score += $weights[$f.Severity]
}
$score = [Math]::Min($score, 100)

if ($score -ge $phishingAt) {
    $verdict = "LIKELY PHISHING"
    $verdictColor = "Red"
    $exitCode = 2
} elseif ($score -ge $suspiciousAt) {
    $verdict = "SUSPICIOUS"
    $verdictColor = "Yellow"
    $exitCode = 1
} else {
    $verdict = "CLEAN"
    $verdictColor = "Green"
    $exitCode = 0
}

# Most severe findings first
$severityRank = @{ High = 0; Medium = 1; Low = 2 }
$sortedFindings = $findings | Sort-Object { $severityRank[$_.Severity] }

# ---------- Output (stage 15 will turn this into a full report) ----------

# Optional detail: every header and the address breakdown
if ($ShowHeaders) {
    Write-Host "=== HEADERS ===" -ForegroundColor Cyan
    foreach ($ph in $parsedHeaders) {
        Write-Host "$($ph.Name): " -ForegroundColor Yellow -NoNewline
        Write-Output $ph.Value
    }

    Write-Host "=== ADDRESSES ===" -ForegroundColor Cyan
    $addressHeaders = [ordered]@{
        "From"        = $fromInfo
        "Reply-To"    = $replyToInfo
        "Return-Path" = $returnPathInfo
    }
    foreach ($label in $addressHeaders.Keys) {
        $info = $addressHeaders[$label]
        Write-Host "${label}: " -ForegroundColor Yellow -NoNewline
        if ($null -eq $info) {
            Write-Output "(none)"
        } else {
            Write-Output "name='$($info.DisplayName)'  address=$($info.Address)  domain=$($info.Domain)"
        }
    }
    Write-Output ""
}

# Summary
Write-Host "phishcheck: $Path" -ForegroundColor Cyan
Write-Output "From:     $(Get-Header 'From')"
Write-Output "Subject:  $(Get-Header 'Subject')"
Write-Output "Auth:     SPF $($auth.spf) | DKIM $($auth.dkim) | DMARC $($auth.dmarc)"
Write-Output ""

# Verdict
Write-Host "VERDICT: $verdict (score $score/100)" -ForegroundColor $verdictColor
Write-Output ""

# Reasons
if ($findings.Count -eq 0) {
    Write-Host "No findings" -ForegroundColor Green
} else {
    Write-Output "Reasons:"
    $colors = @{ High = "Red"; Medium = "Yellow"; Low = "DarkGray" }
    foreach ($f in $sortedFindings) {
        Write-Host ("  [{0,-6}] {1}: {2}" -f $f.Severity, $f.Check, $f.Message) -ForegroundColor $colors[$f.Severity]
    }
}

exit $exitCode
