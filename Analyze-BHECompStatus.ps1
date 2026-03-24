<#
.SYNOPSIS
    Analyses BloodHound Enterprise SharpHound compstatus CSV files and produces
    a categorised HTML report detailing collection failures with remediation guidance.

.DESCRIPTION
    Automatically discovers *_compstatus.csv files in the SearchFolder (defaults to
    the script's own directory). If multiple files are found, presents an interactive
    menu allowing you to analyse a single run or compare across all runs.

    Multi-file mode produces a unified computer list (no duplicates) with a traffic-
    light status per computer across every file analysed:
      Green  — successful in every file it appeared in
      Orange — mixed results across files (some success, some fail)
      Red    — failed in every file it appeared in

    Handles malformed CSV rows caused by long SharpHound error messages that contain
    embedded commas and quotes (common for registry/RPC exceptions).

.PARAMETER OutputFolder
    Folder where the HTML report will be written. Created if it does not exist.
    Defaults to a "Reports" subfolder in the script directory.

.PARAMETER SearchFolder
    Folder to search for *_compstatus.csv files.
    Defaults to the script's own directory.

.PARAMETER ReportTitle
    Optional title prefix for the report.

.PARAMETER NoMenu
    Skip the interactive menu and analyse all discovered CSV files immediately.

.EXAMPLE
    # Run interactively from script directory
    .\Analyze-BHECompStatus.ps1

.EXAMPLE
    # Specify folders explicitly
    .\Analyze-BHECompStatus.ps1 -SearchFolder "C:\BHELogs" -OutputFolder "C:\Reports"

.EXAMPLE
    # Non-interactive - analyse all CSVs found, no prompts
    .\Analyze-BHECompStatus.ps1 -NoMenu

.NOTES
    Author  : SDH / SpecterOps TAM Toolkit
    Version : 2.0
    Requires: PowerShell 5.1+
    Context : BloodHound Enterprise - session and local group collection diagnostics
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder = '',

    [Parameter()]
    [string]$SearchFolder = '',

    [Parameter()]
    [string]$ReportTitle = 'BHE Collection Status Report',

    [Parameter()]
    [switch]$NoMenu
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
#  DEFAULTS
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $SearchFolder) { $SearchFolder = $ScriptDir }
if (-not $OutputFolder)  { $OutputFolder = Join-Path $ScriptDir 'Reports' }

# ---------------------------------------------------------------------------
#  HELPERS
# ---------------------------------------------------------------------------

function HE([string]$s) {
    $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

function Get-StatusCategory([string]$Status) {
    $s = $Status.ToLower().Trim()
    if ($s -eq 'success')                        { return 'Success' }
    if ($s -eq 'notactive')                      { return 'NotActive' }
    if ($s -eq 'portnotopen')                    { return 'PortNotOpen' }
    if ($s -like '*accessdenied*' -or
        $s -like '*access denied*')              { return 'AccessDenied' }
    if ($s -like '*rpc server*')                 { return 'RPCError' }
    if ($s -like '*registry*')                   { return 'RegistryError' }
    if ($s -like '*collector failed*')           { return 'CollectorError' }
    return 'Other'
}

$BadgeColour = @{
    Success        = '#22c55e'
    NotActive      = '#6b7280'
    PortNotOpen    = '#f97316'
    AccessDenied   = '#ef4444'
    RPCError       = '#a855f7'
    RegistryError  = '#ec4899'
    CollectorError = '#f59e0b'
    Other          = '#64748b'
}

function Get-Badge([string]$Cat, [string]$Label = '') {
    $text  = if ($Label) { $Label } else { $Cat }
    $color = if ($BadgeColour.ContainsKey($Cat)) { $BadgeColour[$Cat] } else { '#64748b' }
    return "<span class='badge' style='background:$color'>$(HE $text)</span>"
}

function Get-TLCell([string]$tl) {
    $colors = @{ green = '#22c55e'; orange = '#f97316'; red = '#ef4444' }
    $labels = @{ green = 'OK - All Files'; orange = 'Mixed'; red = 'Failed - All Files' }
    $c = $colors[$tl]
    $l = $labels[$tl]
    return "<span class='tl-badge' style='background:$c'>$l</span>"
}

function Get-TrafficLight($rows) {
    $ok   = @($rows | Where-Object { $_.Category -eq 'Success' }).Count
    $fail = @($rows | Where-Object { $_.Category -ne 'Success' }).Count
    if ($ok -gt 0 -and $fail -eq 0) { return 'green' }
    if ($ok -gt 0 -and $fail -gt 0) { return 'orange' }
    return 'red'
}

function Get-CanonicalName([string]$cn) {
    $cn = $cn.Trim()
    if ($cn -match '^(host|cifs)/(.+)$') { return $Matches[2].ToUpper() }
    return $cn.ToUpper()
}

$Remediation = @{
    NotActive      = '<b>Computer Offline / Unreachable</b><br>The machine did not respond to the availability check. Verify it is powered on, reachable from the collector, and correctly registered in DNS. Stale AD computer objects with no active host will always appear here. Consider scoping collection to active OUs only.'
    PortNotOpen    = '<b>Required Port Blocked</b><br>SharpHound cannot connect. Ensure <b>TCP 445 (SMB)</b> and <b>TCP 135 (RPC Endpoint Mapper)</b> are open from the collector host to the target. Check host-based Windows Firewall on the target, network ACLs, and any security group rules between the collector and target subnet.'
    AccessDenied   = '<b>Access Denied - Insufficient Privileges</b><br><ul><li><b>NetWkstaUserEnum (session data)</b> - requires Local Administrator or a specific grant on the SrvsvcSessionInfo registry ACL on the target machine.</li><li><b>LSAEnumerateAccountsWithUserRight</b> - requires SeSecurityPrivilege or Local Admin. Delegatable via GPO: Computer Configuration &gt; Windows Settings &gt; Security Settings &gt; User Rights Assignment.</li></ul>'
    RPCError       = '<b>RPC Server Unavailable</b><br>TCP 135 is blocked or the target RPC service is not responding. Check: (1) Remote Registry service is started and set to Automatic on the target, (2) TCP 135 is open from the collector, (3) Dynamic RPC ports 49152-65535 are not blocked by an intermediate firewall or Windows Firewall rule.'
    RegistryError  = '<b>Remote Registry Access Denied</b><br>SharpHound tried to read <code>SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0</code> via Remote Registry but was denied. Grant Read access to the collector account for that key via GPO (Security Settings &gt; Registry), or ensure the account is a Local Admin on the target. Also verify the Remote Registry service is running on the target.'
    CollectorError = '<b>Collector-side Exception</b><br>SharpHound threw an unhandled exception. Review the full error detail in the results table. Common causes: WMI timeouts, DNS resolution failures, .NET remoting issues. Ensure the collector host has TCP/UDP line-of-sight to the target on all required protocols.'
    Other          = '<b>Uncategorised Error</b><br>Review the raw status message in the full results table. This may be a newer error type not yet mapped in this script.'
}

function Get-RemediationHtml([string]$Cat) {
    if ($Remediation.ContainsKey($Cat)) { return $Remediation[$Cat] }
    return '<b>No remediation tip available for this category.</b>'
}

# ---------------------------------------------------------------------------
#  CSV PARSER  (robust - handles embedded commas/quotes in long error messages)
# ---------------------------------------------------------------------------

function Import-CompStatusCsv([string]$Path) {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $rawLines  = Get-Content -Path $Path -Encoding UTF8
    $srcFile   = Split-Path $Path -Leaf
    $results   = [System.Collections.Generic.List[PSCustomObject]]::new()

    for ($i = 1; $i -lt $rawLines.Count; $i++) {
        $line = $rawLines[$i].Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $sr     = New-Object System.IO.StringReader($line)
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($sr)
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true

        try {
            $fields = $parser.ReadFields()
            if ($null -eq $fields -or $fields.Count -lt 3) { continue }

            $obj = [PSCustomObject]@{
                ComputerName  = $fields[0].Trim()
                Task          = if ($fields.Count -gt 1) { $fields[1].Trim() } else { '' }
                Status        = if ($fields.Count -gt 2) { $fields[2].Trim() } else { '' }
                IPAddress     = if ($fields.Count -gt 3) { $fields[3].Trim() } else { '' }
                ObjectID      = if ($fields.Count -gt 4) { $fields[4].Trim() } else { '' }
                Category      = ''
                SourceFile    = $srcFile
                LineNumber    = $i + 1
            }
            $obj.Category = Get-StatusCategory -Status $obj.Status
            $results.Add($obj)
        }
        catch { }
        finally { $parser.Dispose() }
    }
    return ,$results
}

# ---------------------------------------------------------------------------
#  DISCOVER CSV FILES
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '  +------------------------------------------------------+' -ForegroundColor Cyan
Write-Host '  |  BloodHound Enterprise - CompStatus Analyser  v2.0  |' -ForegroundColor Cyan
Write-Host '  |  SpecterOps TAM Toolkit                             |' -ForegroundColor Cyan
Write-Host '  +------------------------------------------------------+' -ForegroundColor Cyan
Write-Host ''

$csvFiles = @(Get-ChildItem -Path $SearchFolder -Filter '*compstatus*.csv' -File |
              Sort-Object Name)

if ($csvFiles.Count -eq 0) {
    Write-Host "  [!] No *compstatus*.csv files found in: $SearchFolder" -ForegroundColor Red
    Write-Host "      Place your CSV files in the same folder as this script, or use -SearchFolder." -ForegroundColor Yellow
    exit 1
}

Write-Host "  [*] Found $($csvFiles.Count) compstatus file(s) in: $SearchFolder" -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
#  MENU
# ---------------------------------------------------------------------------

$selectedFiles = @()

if ($csvFiles.Count -eq 1 -or $NoMenu) {
    $selectedFiles = $csvFiles
    if ($csvFiles.Count -eq 1) {
        Write-Host "  [*] Single file found - running analysis automatically." -ForegroundColor Cyan
        Write-Host "      $($csvFiles[0].Name)" -ForegroundColor White
    }
    else {
        Write-Host "  [*] -NoMenu specified - analysing all $($csvFiles.Count) files." -ForegroundColor Cyan
    }
}
else {
    Write-Host '  Select an option:' -ForegroundColor Yellow
    Write-Host ''
    for ($m = 0; $m -lt $csvFiles.Count; $m++) {
        $f    = $csvFiles[$m]
        $size = '{0:N0} KB' -f [math]::Ceiling($f.Length / 1KB)
        Write-Host ("    [{0}]  {1}   ({2})" -f ($m + 1), $f.Name, $size) -ForegroundColor White
    }
    Write-Host ''
    Write-Host ("    [{0}]  Compare ALL {1} files - cross-run report" -f ($csvFiles.Count + 1), $csvFiles.Count) -ForegroundColor Cyan
    Write-Host ''

    $choice = 0
    do {
        $raw   = Read-Host '  Enter choice'
        $valid = [int]::TryParse($raw.Trim(), [ref]$choice) -and
                 $choice -ge 1 -and $choice -le ($csvFiles.Count + 1)
        if (-not $valid) {
            Write-Host "  [!] Invalid choice. Enter a number between 1 and $($csvFiles.Count + 1)." -ForegroundColor Red
        }
    } while (-not $valid)

    if ($choice -le $csvFiles.Count) {
        $selectedFiles = @($csvFiles[$choice - 1])
        Write-Host ''
        Write-Host "  [*] Analysing: $($selectedFiles[0].Name)" -ForegroundColor Cyan
    }
    else {
        $selectedFiles = $csvFiles
        Write-Host ''
        Write-Host "  [*] Multi-file comparison mode - $($csvFiles.Count) files" -ForegroundColor Cyan
    }
}

Write-Host ''

# ---------------------------------------------------------------------------
#  PARSE ALL SELECTED FILES
# ---------------------------------------------------------------------------

$allRows   = [System.Collections.Generic.List[PSCustomObject]]::new()
$fileStats = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($f in $selectedFiles) {
    Write-Host "  [>] Parsing: $($f.Name)" -ForegroundColor Gray
    $rows = Import-CompStatusCsv -Path $f.FullName
    $fileStats.Add([PSCustomObject]@{
        FileName    = $f.Name
        TotalRows   = $rows.Count
        SuccessRows = @($rows | Where-Object { $_.Category -eq 'Success' }).Count
        FailRows    = @($rows | Where-Object { $_.Category -ne 'Success' }).Count
    })
    foreach ($r in $rows) { $allRows.Add($r) }
}

$isMultiFile = ($selectedFiles.Count -gt 1)

# ---------------------------------------------------------------------------
#  ANALYSIS
# ---------------------------------------------------------------------------

$successRows = @($allRows | Where-Object { $_.Category -eq 'Success' })
$failRows    = @($allRows | Where-Object { $_.Category -ne 'Success' })
$totalRows   = $allRows.Count
$pctSuccess  = if ($totalRows -gt 0) { [math]::Round($successRows.Count / $totalRows * 100, 1) } else { 0 }
$pctFail     = if ($totalRows -gt 0) { [math]::Round($failRows.Count    / $totalRows * 100, 1) } else { 0 }

# Deduplicated computer map
$compMap = @{}
foreach ($r in $allRows) {
    $key = Get-CanonicalName $r.ComputerName
    if (-not $compMap.ContainsKey($key)) {
        $compMap[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $compMap[$key].Add($r)
}

$uniqueComputers   = $compMap.Count
$notActiveOnly     = @($compMap.GetEnumerator() | Where-Object {
    $all = @($_.Value)
    $all.Count -eq 1 -and $all[0].Status -eq 'NotActive'
})
$taskFailComputers = @($compMap.GetEnumerator() | Where-Object {
    $fails = @($_.Value | Where-Object { $_.Task -ne 'ComputerAvailability' -and $_.Category -ne 'Success' })
    $fails.Count -gt 0
})
$fullyOkComputers  = @($compMap.GetEnumerator() | Where-Object {
    $fails = @($_.Value | Where-Object { $_.Category -ne 'Success' })
    $fails.Count -eq 0
})
$problemComputers  = @($compMap.GetEnumerator() | Where-Object {
    $fails = @($_.Value | Where-Object { $_.Category -ne 'Success' })
    $fails.Count -gt 0
} | Sort-Object Name)

$catGroups = $failRows | Group-Object Category | Sort-Object Count -Descending

# Build computer JSON data for spotlight search
$compJsonParts = foreach ($entry in $compMap.GetEnumerator()) {
    $jg    = @($entry.Value)
    $jok   = @($jg | Where-Object { $_.Category -eq 'Success' }).Count
    $jfail = @($jg | Where-Object { $_.Category -ne 'Success' }).Count
    $jcats = (@($jg | Select-Object -ExpandProperty Category -Unique | Sort-Object)) -join ','
    $jips  = (@($jg | Select-Object -ExpandProperty IPAddress -Unique | Where-Object { $_ -and $_ -ne 'Unknown' })) -join ','
    $jlinesByFile = $jg | Group-Object SourceFile | Sort-Object Name | ForEach-Object {
        $jnums = (@($_.Group | Select-Object -ExpandProperty LineNumber | Sort-Object -Unique)) -join ','
        "$($_.Name):$jnums"
    }
    $jlines = $jlinesByFile -join ' | '
    $jtl   = Get-TrafficLight $jg
    $jn    = $entry.Name.Replace('\','\\').Replace('"','\"')
    '{"n":"' + $jn + '","ip":"' + $jips + '","ok":' + $jok + ',"fail":' + $jfail + ',"cats":"' + $jcats + '","lines":"' + $jlines + '","tl":"' + $jtl + '"}'
}
$computerJsonData = '[' + ($compJsonParts -join ',') + ']'

# ---------------------------------------------------------------------------
#  BUILD HTML SECTIONS
# ---------------------------------------------------------------------------

# File stats table (multi-file only)
$fileStatsHtml = ''
if ($isMultiFile) {
    $fsRowsHtml = foreach ($fs in $fileStats) {
        $pct = if ($fs.TotalRows -gt 0) { [math]::Round($fs.SuccessRows / $fs.TotalRows * 100, 1) } else { 0 }
        $tl  = if ($fs.FailRows -eq 0) { 'green' } elseif ($fs.SuccessRows -gt 0) { 'orange' } else { 'red' }
        $tlc = Get-TLCell $tl
        "<tr><td>$(HE $fs.FileName)</td><td style='text-align:center'>$($fs.TotalRows)</td><td style='text-align:center;color:#22c55e'>$($fs.SuccessRows)</td><td style='text-align:center;color:#ef4444'>$($fs.FailRows)</td><td style='text-align:center'>$pct%</td><td style='text-align:center'>$tlc</td></tr>"
    }
    $fileStatsHtml = "<section id='sec-files'><div class='sec-hdr' onclick=""toggleSec('sec-files')""><h2>&#128193; FILES ANALYSED ($($selectedFiles.Count))</h2><span class='collapse-btn' id='sec-files-btn'>&#9660;</span></div><div id='sec-files-body'><div class='table-wrap'><table><thead><tr><th>File</th><th>Total Rows</th><th>Success</th><th>Failed</th><th>Success %</th><th>Status</th></tr></thead><tbody>$($fsRowsHtml -join '')</tbody></table></div></div></section>"
}

# Computer summary rows
$compSummaryRows = foreach ($entry in $problemComputers) {
    $g      = @($entry.Value)
    $ok     = @($g | Where-Object { $_.Category -eq 'Success' }).Count
    $fail   = @($g | Where-Object { $_.Category -ne 'Success' }).Count
    $cats   = @($g | Where-Object { $_.Category -ne 'Success' } | Select-Object -ExpandProperty Category -Unique | Sort-Object)
    $ips    = @($g | Select-Object -ExpandProperty IPAddress -Unique | Where-Object { $_ -and $_ -ne 'Unknown' })
    $ip     = if ($ips) { ($ips | Sort-Object -Unique) -join ', ' } else { 'Unknown' }
    $tl     = Get-TrafficLight $g
    $tlCell = Get-TLCell $tl
    $badgesHtml = ($cats | ForEach-Object { Get-Badge $_ }) -join ' '
    # Group line numbers by source file for the cell display
    $lineNumsByFile = $g | Group-Object SourceFile | Sort-Object Name | ForEach-Object {
        $nums = (@($_.Group | Select-Object -ExpandProperty LineNumber | Sort-Object -Unique)) -join ', '
        "$($_.Name): $nums"
    }
    $lineNums = $lineNumsByFile -join ' | '
    $srcCol = ''
    if ($isMultiFile) {
        $fl = (@($g | Select-Object -ExpandProperty SourceFile -Unique | Sort-Object)) -join '<br>'
        $srcCol = "<td class='status-cell'>$fl</td>"
    }
    $cid = 'comp-' + ($entry.Name -replace '[^a-zA-Z0-9\-_]','-')
    "<tr id='$cid'><td>$(HE $entry.Name)</td><td>$(HE $ip)</td><td style='text-align:center'>$ok</td><td style='text-align:center'>$fail</td><td>$badgesHtml</td><td style='text-align:center'>$tlCell</td><td style='font-family:Consolas,monospace;font-size:11px;color:var(--muted)'>$(HE $lineNums)</td>$srcCol</tr>"
}
$compSrcHeader = if ($isMultiFile) { '<th>Source File(s)</th>' } else { '' }

# Failure rows
$failRowIdx = 0
$failTableRows = foreach ($r in ($failRows | Sort-Object Category, ComputerName)) {
    $statusShort = $r.Status.Substring(0, [Math]::Min($r.Status.Length, 300))
    $srcCol      = if ($isMultiFile) { "<td class='status-cell'>$(HE $r.SourceFile)</td>" } else { '' }
    $fcn         = Get-CanonicalName $r.ComputerName
    "<tr id='fr-$failRowIdx' data-comp='$(HE $fcn)'><td>$(HE $fcn)</td><td>$(HE $r.Task)</td><td>$(Get-Badge $r.Category)</td><td class='status-cell'>$(HE $statusShort)</td><td>$(HE $r.IPAddress)</td><td style='font-family:Consolas,monospace;font-size:11px;color:var(--muted)'><span style='color:#64748b'>$(HE $r.SourceFile)</span><br>L$($r.LineNumber)</td>$srcCol</tr>"
    $failRowIdx++
}
$failSrcHeader = if ($isMultiFile) { '<th>Source File</th>' } else { '' }

# Remediation cards
$remCards = foreach ($cg in ($catGroups | Where-Object { $_.Name -ne 'Success' })) {
    $cat      = $cg.Name
    $color    = if ($BadgeColour.ContainsKey($cat)) { $BadgeColour[$cat] } else { '#64748b' }
    $tip      = Get-RemediationHtml -Cat $cat
    $affected = ($allRows | Where-Object { $_.Category -eq $cat } |
                 Select-Object -ExpandProperty ComputerName -Unique |
                 ForEach-Object { Get-CanonicalName $_ } | Sort-Object -Unique) -join ', '
    "<div class='remediation-card' style='border-left:4px solid $color'><h3>$(Get-Badge $cat) &nbsp; $($cg.Count) occurrence(s)</h3><p>$tip</p><p><b>Affected computers:</b><br><code>$(HE $affected)</code></p></div>"
}

# Not active
$notActiveHtml = ($notActiveOnly | Select-Object -ExpandProperty Name | Sort-Object) -join '<br>'

# Multi-file cross-run table
$multiCompTableHtml = ''
if ($isMultiFile) {
    $mcRows = foreach ($entry in ($compMap.GetEnumerator() | Sort-Object Name)) {
        $g      = @($entry.Value)
        $tl     = Get-TrafficLight $g
        $tlCell = Get-TLCell $tl
        $ips    = @($g | Select-Object -ExpandProperty IPAddress -Unique | Where-Object { $_ -and $_ -ne 'Unknown' })
        $ip     = if ($ips) { ($ips | Sort-Object -Unique) -join ', ' } else { 'Unknown' }
        $errFiles = @($g | Where-Object { $_.Category -ne 'Success' } |
                      Select-Object -ExpandProperty SourceFile -Unique | Sort-Object)
        $fileTagsHtml = if ($errFiles) {
            ($errFiles | ForEach-Object { "<span class='file-tag'>$(HE $_)</span>" }) -join ' '
        } else { '<span style="color:#22c55e">None - all clean</span>' }
        "<tr><td>$(HE $entry.Name)</td><td>$(HE $ip)</td><td style='text-align:center'>$tlCell</td><td>$fileTagsHtml</td></tr>"
    }
    $multiCompTableHtml = "<section id='sec-crossrun'><div class='sec-hdr' onclick=""toggleSec('sec-crossrun')""><h2>&#128201; ALL COMPUTERS - CROSS-RUN STATUS ($uniqueComputers unique)</h2><span class='collapse-btn' id='sec-crossrun-btn'>&#9660;</span></div><div id='sec-crossrun-body'><p style='color:var(--muted);font-size:13px;margin-bottom:12px'>Each computer listed once. Green = OK in all files. Orange = mixed results. Red = failed in every file it appeared in.</p><input class='table-search' type='text' id='mcSearch' placeholder='Filter computers...' oninput=""filterTable('mcTable','mcSearch')""><div class='table-wrap'><table id='mcTable'><thead><tr><th>Computer</th><th>IP Address</th><th>Status</th><th>Files Containing Errors</th></tr></thead><tbody>$($mcRows -join '')</tbody></table></div></div></section>"
}

# Full audit log
$allRowIdx = 0
$allTableRows = foreach ($r in ($allRows | Sort-Object ComputerName, Task)) {
    $rowClass    = if ($r.Category -eq 'Success') { 'row-ok' } else { 'row-fail' }
    $statusShort = $r.Status.Substring(0, [Math]::Min($r.Status.Length, 300))
    $srcCol      = if ($isMultiFile) { "<td class='status-cell'>$(HE $r.SourceFile)</td>" } else { '' }
    $acn         = Get-CanonicalName $r.ComputerName
    "<tr id='ar-$allRowIdx' class='$rowClass' data-comp='$(HE $acn)'><td>$(HE $acn)</td><td>$(HE $r.Task)</td><td>$(Get-Badge $r.Category)</td><td class='status-cell'>$(HE $statusShort)</td><td>$(HE $r.IPAddress)</td><td style='font-family:Consolas,monospace;font-size:11px;color:var(--muted)'><span style='color:#64748b'>$(HE $r.SourceFile)</span><br>L$($r.LineNumber)</td>$srcCol</tr>"
    $allRowIdx++
}
$allSrcHeader = if ($isMultiFile) { '<th>Source File</th>' } else { '' }

# Chart
$chartLabels = ($catGroups | ForEach-Object { "'" + (HE $_.Name) + "'" }) -join ','
$chartValues = ($catGroups | ForEach-Object { $_.Count }) -join ','
$chartColors = ($catGroups | ForEach-Object {
    "'" + $(if ($BadgeColour.ContainsKey($_.Name)) { $BadgeColour[$_.Name] } else { '#64748b' }) + "'"
}) -join ','

# ---------------------------------------------------------------------------
#  ASSEMBLE HTML
# ---------------------------------------------------------------------------

$reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$fileLabel  = if ($isMultiFile) {
    "$($selectedFiles.Count) files ($($selectedFiles[0].Name) to $($selectedFiles[-1].Name))"
} else { $selectedFiles[0].Name }
$modeLabel  = if ($isMultiFile) { 'Multi-Run Comparison' } else { 'Single Run' }
$fullTitle  = "$ReportTitle - $modeLabel"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$fullTitle</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#273449;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--danger:#ef4444;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;}
a{color:var(--accent);}

/* Header */
header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 32px;display:flex;align-items:center;gap:16px;}
.logo{font-size:30px;}
header h1{font-size:18px;font-weight:700;color:var(--accent);}
.meta{font-size:12px;color:var(--muted);margin-top:2px;}
.mode-pill{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700;background:#1d4ed8;color:#fff;margin-left:8px;vertical-align:middle;}

/* Spotlight bar */
#spotlight-wrap{background:#162032;border-bottom:2px solid var(--accent);padding:10px 32px;position:sticky;top:0;z-index:200;}
.spotlight-inner{display:flex;align-items:center;gap:10px;max-width:1360px;margin:0 auto;position:relative;}
.spotlight-label{font-size:12px;color:var(--accent);white-space:nowrap;font-weight:600;}
#spotlight-input{flex:1;max-width:580px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:7px 13px;font-size:13px;}
#spotlight-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(56,189,248,.15);}
#sp-clear{background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px;padding:0 4px;line-height:1;}
#sp-clear:hover{color:var(--text);}
.spotlight-hint{font-size:11px;color:var(--muted);white-space:nowrap;}
/* Results panel: absolute dropdown so it floats OVER page content, never inside sticky height */
#spotlight-results{
  position:absolute;
  top:calc(100% + 8px);
  left:0;right:0;
  background:#162032;
  border:1px solid var(--accent);
  border-radius:8px;
  padding:12px 14px;
  display:none;
  z-index:300;
  max-height:70vh;
  overflow-y:auto;
  box-shadow:0 8px 32px rgba(0,0,0,.6);
}
.sp-cards{display:flex;flex-direction:column;gap:10px;}
.sp-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 15px;width:100%;}
.sp-card-hdr{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:6px;}
.sp-name{font-weight:700;font-size:13px;font-family:Consolas,monospace;color:var(--text);word-break:break-all;flex:1;}
.sp-card-meta{font-size:12px;color:var(--muted);margin-bottom:6px;display:flex;flex-direction:column;gap:3px;}
.sp-card-meta-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.sp-card-meta code{background:var(--bg);padding:1px 5px;border-radius:3px;font-family:Consolas,monospace;}
.sp-card-cats{margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px;}
.sp-card-links{display:flex;gap:8px;flex-wrap:wrap;}
.sp-link{font-size:12px;padding:3px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--accent);text-decoration:none;cursor:pointer;}
.sp-link:hover{border-color:var(--accent);background:var(--surface2);}
.sp-notfound{color:#f59e0b;font-size:12px;padding:6px 0;font-style:italic;}

/* Layout */
.container{max-width:1360px;margin:0 auto;padding:20px 32px;}
section{margin-bottom:28px;}

/* Collapsible sections */
.sec-hdr{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding-bottom:8px;border-bottom:1px solid var(--border);margin-bottom:14px;user-select:none;}
.sec-hdr h2{border-bottom:none;padding-bottom:0;margin-bottom:0;font-size:13px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;}
.sec-hdr:hover h2{color:var(--text);}
.sec-hdr-right{display:flex;align-items:center;gap:8px;}
.collapse-btn{color:var(--muted);font-size:11px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:2px 9px;font-family:Consolas,monospace;}
.sec-body{overflow:hidden;}

/* Stat cards */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:12px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px;}
.stat-card .val{font-size:28px;font-weight:700;line-height:1.1;}
.stat-card .lbl{font-size:12px;color:var(--muted);margin-top:3px;}
.stat-card.success .val{color:var(--success);}
.stat-card.danger .val{color:var(--danger);}
.stat-card.warn .val{color:#f97316;}
.stat-card.info .val{color:var(--accent);}
.stat-card.clickable{cursor:pointer;transition:border-color .15s,transform .1s;}
.stat-card.clickable:hover{border-color:var(--accent);transform:translateY(-2px);}
.stat-card .lbl .arr{font-size:10px;opacity:.6;}

/* Chart */
.chart-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;display:flex;align-items:center;gap:32px;flex-wrap:wrap;}
.chart-wrap canvas{max-height:200px;max-width:200px;}
.chart-legend{display:flex;flex-direction:column;gap:9px;}
.chart-legend-item{display:flex;align-items:center;gap:8px;font-size:13px;}
.chart-legend-dot{width:11px;height:11px;border-radius:50%;flex-shrink:0;}

/* Tables */
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border);}
table{width:100%;border-collapse:collapse;}
thead th{background:var(--surface2);padding:9px 13px;text-align:left;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;}
tbody tr{border-top:1px solid var(--border);}
tbody tr:hover{background:var(--surface2);}
tbody td{padding:8px 13px;vertical-align:top;}
.status-cell{font-size:12px;color:var(--muted);max-width:380px;word-break:break-word;}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap;}
.tl-badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:700;color:#fff;}
.file-tag{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:11px;font-family:Consolas,monospace;margin:1px 2px;}

/* Remediation cards */
.remediation-card{background:var(--surface);border-radius:8px;padding:14px 18px;margin-bottom:11px;}
.remediation-card p,.remediation-card ul{color:var(--muted);font-size:13px;margin-bottom:5px;}
.remediation-card ul{margin-left:18px;}
.remediation-card code{background:var(--surface2);padding:1px 5px;border-radius:3px;font-family:Consolas,monospace;font-size:12px;word-break:break-all;}

/* Not-active body */
.details-body{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px 18px;font-size:13px;color:var(--muted);line-height:1.9;}

/* Search */
.table-search{width:100%;max-width:360px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:7px 12px;font-size:13px;margin-bottom:10px;}
.table-search:focus{outline:none;border-color:var(--accent);}

/* Row highlight */
@keyframes rowFlash{0%{background:#1e3a5f;}60%{background:#1e3a5f;}100%{background:transparent;}}
.highlight-row td{animation:rowFlash 1.8s ease-out;}

footer{text-align:center;padding:22px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);margin-top:36px;}
</style>
</head>
<body>

<header>
  <div class="logo">&#129405;</div>
  <div>
    <h1>$fullTitle <span class="mode-pill">$modeLabel</span></h1>
    <div class="meta">Source: <code>$fileLabel</code> &nbsp;|&nbsp; Generated: $reportDate &nbsp;|&nbsp; BloodHound Enterprise &#8212; SharpHound Collection Diagnostics</div>
  </div>
</header>

<!-- ═══ SPOTLIGHT SEARCH ═══ -->
<div id="spotlight-wrap">
  <div class="spotlight-inner">
    <span class="spotlight-label">&#128269; Computer Search</span>
    <input id="spotlight-input" type="text" placeholder="Type a computer name (comma-separate for multiple)  e.g.  DC01, SERVER02, WORKSTATION01" autocomplete="off">
    <button id="sp-clear" onclick="clearSpotlight()" title="Clear search">&#10005;</button>
    <span class="spotlight-hint">Comma-separate for multiple</span>
    <!-- Dropdown panel is absolute child of .spotlight-inner so it floats over page -->
    <div id="spotlight-results"><div class="sp-cards" id="sp-cards"></div></div>
  </div>
</div>

<div class="container">

<!-- ═══ SUMMARY ═══ -->
<section id="sec-summary">
  <div class="sec-hdr" onclick="toggleSec('sec-summary')">
    <h2>&#128202; Summary</h2>
    <div class="sec-hdr-right"><span style="font-size:11px;color:var(--muted)">click to collapse</span><span class="collapse-btn" id="sec-summary-btn">&#9660;</span></div>
  </div>
  <div id="sec-summary-body">
    <div class="stat-grid">
      <div class="stat-card info clickable" onclick="clearAllTableFilters();jumpTo('sec-audit')" title="Jump to Full Audit Log (all results)">
        <div class="val">$totalRows</div><div class="lbl">Total task results <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card info clickable" onclick="clearAllTableFilters();jumpTo('sec-issues')" title="Jump to Computers with Issues">
        <div class="val">$uniqueComputers</div><div class="lbl">Unique computers <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card success clickable" onclick="clearAllTableFilters();jumpTo('sec-audit')" title="Jump to Full Audit Log (all results)">
        <div class="val">$($successRows.Count)</div><div class="lbl">Successful ($pctSuccess%) <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card danger clickable" onclick="clearAllTableFilters();jumpTo('sec-failures')" title="Jump to All Failures">
        <div class="val">$($failRows.Count)</div><div class="lbl">Failed ($pctFail%) <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card warn clickable" onclick="clearAllTableFilters();jumpTo('sec-notactive')" title="Jump to Not Active list">
        <div class="val">$($notActiveOnly.Count)</div><div class="lbl">Not Active computers <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card success clickable" onclick="clearAllTableFilters();jumpTo('sec-issues')" title="Jump to Computers with Issues">
        <div class="val">$($fullyOkComputers.Count)</div><div class="lbl">Fully successful <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card danger clickable" onclick="clearAllTableFilters();jumpTo('sec-issues')" title="Jump to Task-level errors">
        <div class="val">$($taskFailComputers.Count)</div><div class="lbl">Task-level errors <span class="arr">&#8599;</span></div>
      </div>
    </div>
  </div>
</section>

$fileStatsHtml

<!-- ═══ CHART ═══ -->
<section id="sec-chart">
  <div class="sec-hdr" onclick="toggleSec('sec-chart')">
    <h2>&#128200; Failure Distribution</h2>
    <span class="collapse-btn" id="sec-chart-btn">&#9660;</span>
  </div>
  <div id="sec-chart-body">
    <div class="chart-wrap">
      <canvas id="donut" width="200" height="200"></canvas>
      <div class="chart-legend" id="legend"></div>
    </div>
  </div>
</section>

$multiCompTableHtml

<!-- ═══ COMPUTERS WITH ISSUES ═══ -->
<section id="sec-issues">
  <div class="sec-hdr" onclick="toggleSec('sec-issues')">
    <h2>&#128421; Computers with Issues &#8212; Task Detail</h2>
    <span class="collapse-btn" id="sec-issues-btn">&#9660;</span>
  </div>
  <div id="sec-issues-body">
    <input class="table-search" type="text" id="compSearch" placeholder="Filter computers..." oninput="filterTable('compTable','compSearch')">
    <div class="table-wrap">
    <table id="compTable">
    <thead><tr><th>Computer</th><th>IP Address</th><th>&#10004; OK</th><th>&#10008; Failed</th><th>Error Categories</th><th>Status</th><th>File / Line(s)</th>$compSrcHeader</tr></thead>
    <tbody>$($compSummaryRows -join '')</tbody>
    </table>
    </div>
  </div>
</section>

<!-- ═══ ALL FAILURES ═══ -->
<section id="sec-failures">
  <div class="sec-hdr" onclick="toggleSec('sec-failures')">
    <h2>&#10060; All Failed Results</h2>
    <span class="collapse-btn" id="sec-failures-btn">&#9660;</span>
  </div>
  <div id="sec-failures-body">
    <input class="table-search" type="text" id="failSearch" placeholder="Filter by computer, task, or status..." oninput="filterTable('failTable','failSearch')">
    <div class="table-wrap">
    <table id="failTable">
    <thead><tr><th>Computer</th><th>Task</th><th>Category</th><th>Status Detail</th><th>IP</th><th>File / Line</th>$failSrcHeader</tr></thead>
    <tbody>$($failTableRows -join '')</tbody>
    </table>
    </div>
  </div>
</section>

<!-- ═══ REMEDIATION ═══ -->
<section id="sec-remediation">
  <div class="sec-hdr" onclick="toggleSec('sec-remediation')">
    <h2>&#128295; Remediation Guidance</h2>
    <span class="collapse-btn" id="sec-remediation-btn">&#9660;</span>
  </div>
  <div id="sec-remediation-body">
    $($remCards -join '')
  </div>
</section>

<!-- ═══ NOT ACTIVE ═══ -->
<section id="sec-notactive">
  <div class="sec-hdr" onclick="toggleSec('sec-notactive')">
    <h2>&#128164; Not Active Computers ($($notActiveOnly.Count))</h2>
    <span class="collapse-btn" id="sec-notactive-btn">&#9660;</span>
  </div>
  <div id="sec-notactive-body">
    <div class="details-body">$notActiveHtml</div>
  </div>
</section>

<!-- ═══ FULL AUDIT LOG ═══ -->
<section id="sec-audit">
  <div class="sec-hdr" onclick="toggleSec('sec-audit')">
    <h2>&#128203; Full Audit Log &#8212; All Results</h2>
    <span class="collapse-btn" id="sec-audit-btn">&#9660;</span>
  </div>
  <div id="sec-audit-body">
    <input class="table-search" type="text" id="allSearch" placeholder="Filter all results..." oninput="filterTable('allTable','allSearch')">
    <div class="table-wrap">
    <table id="allTable">
    <thead><tr><th>Computer</th><th>Task</th><th>Category</th><th>Status Detail</th><th>IP</th><th>File / Line</th>$allSrcHeader</tr></thead>
    <tbody>$($allTableRows -join '')</tbody>
    </table>
    </div>
  </div>
</section>

</div>
<footer>BloodHound Enterprise &#8212; SharpHound CompStatus Analyser v2.1 &nbsp;|&nbsp; SpecterOps TAM Toolkit &nbsp;|&nbsp; $reportDate</footer>

<script>
// ── Chart ──────────────────────────────────────────────────────────────────
var chartLabels=[$chartLabels],chartValues=[$chartValues],chartColors=[$chartColors];
new Chart(document.getElementById('donut'),{
  type:'doughnut',
  data:{labels:chartLabels,datasets:[{data:chartValues,backgroundColor:chartColors,borderWidth:2,borderColor:'#1e293b'}]},
  options:{cutout:'65%',plugins:{legend:{display:false},tooltip:{callbacks:{
    label:function(ctx){
      var total=chartValues.reduce(function(a,b){return a+b},0);
      return ' '+ctx.label+': '+ctx.raw+' ('+(ctx.raw/total*100).toFixed(1)+'%)';
    }
  }}}}
});
var leg=document.getElementById('legend');
chartLabels.forEach(function(l,i){
  var d=document.createElement('div');d.className='chart-legend-item';
  d.innerHTML='<div class="chart-legend-dot" style="background:'+chartColors[i]+'"></div><span><b>'+chartValues[i]+'</b> -- '+l+'</span>';
  leg.appendChild(d);
});

// ── Section toggle ─────────────────────────────────────────────────────────
function toggleSec(id){
  var body=document.getElementById(id+'-body');
  var btn=document.getElementById(id+'-btn');
  if(!body) return;
  if(body.style.display==='none'){
    body.style.display='';
    if(btn) btn.innerHTML='&#9660;';
  } else {
    body.style.display='none';
    if(btn) btn.innerHTML='&#9654;';
  }
}

function jumpTo(secId){
  var body=document.getElementById(secId+'-body');
  var btn=document.getElementById(secId+'-btn');
  if(body && body.style.display==='none'){
    body.style.display='';
    if(btn) btn.innerHTML='&#9660;';
  }
  var el=document.getElementById(secId);
  if(!el) return;
  // Use two rAF frames to ensure layout reflow after display change settles,
  // then manually calculate offset to account for sticky spotlight bar height
  requestAnimationFrame(function(){
    requestAnimationFrame(function(){
      var stickyH=0;
      var sw=document.getElementById('spotlight-wrap');
      if(sw) stickyH=sw.getBoundingClientRect().height;
      var rect=el.getBoundingClientRect();
      var scrollTop=window.pageYOffset||document.documentElement.scrollTop;
      var target=scrollTop+rect.top-stickyH-12;
      window.scrollTo({top:target,behavior:'smooth'});
    });
  });
}

// ── Table filter ───────────────────────────────────────────────────────────
function filterTable(tid,sid){
  var q=document.getElementById(sid).value.toLowerCase();
  var rows=document.querySelectorAll('#'+tid+' tbody tr');
  for(var i=0;i<rows.length;i++){
    rows[i].style.display=rows[i].textContent.toLowerCase().indexOf(q)>=0?'':'none';
  }
}

// ── Row highlight ──────────────────────────────────────────────────────────
function highlightRow(rowId){
  var el=document.getElementById(rowId);
  if(!el) return;
  var sec=el.closest('section');
  if(sec){
    var body=document.getElementById(sec.id+'-body');
    var btn=document.getElementById(sec.id+'-btn');
    if(body && body.style.display==='none'){
      body.style.display='';
      if(btn) btn.innerHTML='&#9660;';
    }
  }
  requestAnimationFrame(function(){
    requestAnimationFrame(function(){
      var stickyH=0;
      var sw=document.getElementById('spotlight-wrap');
      if(sw) stickyH=sw.getBoundingClientRect().height;
      var rect=el.getBoundingClientRect();
      var scrollTop=window.pageYOffset||document.documentElement.scrollTop;
      var target=scrollTop+rect.top-stickyH-40;
      window.scrollTo({top:target,behavior:'smooth'});
      el.classList.add('highlight-row');
      setTimeout(function(){ el.classList.remove('highlight-row'); },2000);
    });
  });
}

// ── Spotlight computer search ──────────────────────────────────────────────
var COMP_DATA=$computerJsonData;
var compIdx={};
for(var i=0;i<COMP_DATA.length;i++){ compIdx[COMP_DATA[i].n.toUpperCase()]=COMP_DATA[i]; }

var spotTimer;
document.getElementById('spotlight-input').addEventListener('input',function(){
  clearTimeout(spotTimer);
  spotTimer=setTimeout(runSpotlight,220);
});
document.getElementById('spotlight-input').addEventListener('keydown',function(e){
  if(e.key==='Escape') clearSpotlight();
});

function runSpotlight(){
  var raw=document.getElementById('spotlight-input').value;
  var terms=raw.split(',').map(function(s){return s.trim().toUpperCase();}).filter(function(s){return s.length>0;});
  var panel=document.getElementById('spotlight-results');
  var cards=document.getElementById('sp-cards');
  if(terms.length===0){ panel.style.display='none'; cards.innerHTML=''; return; }

  var matches=[]; var notFound=[];
  var keys=Object.keys(compIdx);
  for(var t=0;t<terms.length;t++){
    var term=terms[t];
    if(compIdx[term]){ matches.push(compIdx[term]); continue; }
    // partial / contains search
    var found=null;
    for(var k=0;k<keys.length;k++){
      if(keys[k].indexOf(term)>=0){ found=compIdx[keys[k]]; break; }
    }
    if(found) matches.push(found);
    else notFound.push(terms[t]);
  }

  // deduplicate matches
  var seen={};
  var uniq=matches.filter(function(m){ if(seen[m.n]) return false; seen[m.n]=1; return true; });

  var html='';
  for(var i=0;i<uniq.length;i++) html+=renderSpCard(uniq[i]);
  if(notFound.length>0) html+='<div class="sp-notfound">Not found: '+notFound.join(', ')+'</div>';
  cards.innerHTML=html;
  panel.style.display='block';
}

function catColor(cat){
  var m={Success:'#22c55e',NotActive:'#6b7280',PortNotOpen:'#f97316',AccessDenied:'#ef4444',RPCError:'#a855f7',RegistryError:'#ec4899',CollectorError:'#f59e0b',Other:'#64748b'};
  return m[cat.trim()]||'#64748b';
}

function renderSpCard(c){
  var tlColor={green:'#22c55e',orange:'#f97316',red:'#ef4444'}[c.tl]||'#6b7280';
  var tlLabel={green:'All OK',orange:'Mixed',red:'All Failed'}[c.tl]||c.tl;
  var catHtml='';
  if(c.cats){
    var cl=c.cats.split(',').filter(function(x){return x.trim();});
    for(var i=0;i<cl.length;i++) catHtml+='<span class="badge" style="background:'+catColor(cl[i].trim())+'">'+cl[i].trim()+'</span> ';
  }
  var n=c.n;
  var ns=n.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  return '<div class="sp-card">'
    +'<div class="sp-card-hdr">'
    +'<span class="sp-name">'+n+'</span>'
    +'<span class="tl-badge" style="background:'+tlColor+'">'+tlLabel+'</span>'
    +'</div>'
    +'<div class="sp-card-meta">'
    +'<div class="sp-card-meta-row">'
    +(c.ip?'<span>IP: <code>'+c.ip+'</code></span>':'<span style="color:#6b7280">IP: Unknown</span>')
    +'<span style="color:#22c55e">&#10004; '+c.ok+' ok</span>'
    +'<span style="color:#ef4444">&#10008; '+c.fail+' failed</span>'
    +'</div>'
    +(c.lines?'<div class="sp-card-meta-row"><span style="color:#94a3b8">CSV line(s): <code>'+c.lines+'</code></span></div>':'')
    +'</div>'
    +(catHtml?'<div class="sp-card-cats">'+catHtml+'</div>':'')
    +'<div class="sp-card-links">'
    +'<a class="sp-link" href="#" onclick="spJumpIssues(\''+ns+'\');return false;">&#128421; Issues Table</a>'
    +'<a class="sp-link" href="#" onclick="spJumpAudit(\''+ns+'\');return false;">&#128203; Audit Log</a>'
    +'<a class="sp-link" href="#" onclick="spJumpFailures(\''+ns+'\');return false;">&#10060; Failures Only</a>'
    +'</div>'
    +'</div>';
}

function spJumpIssues(name){
  jumpTo('sec-issues');
  var inp=document.getElementById('compSearch');
  inp.value=name; filterTable('compTable','compSearch');
  return false;
}
function spJumpAudit(name){
  jumpTo('sec-audit');
  var inp=document.getElementById('allSearch');
  inp.value=name; filterTable('allTable','allSearch');
  return false;
}
function spJumpFailures(name){
  jumpTo('sec-failures');
  var inp=document.getElementById('failSearch');
  inp.value=name; filterTable('failTable','failSearch');
  return false;
}

function clearAllTableFilters(){
  var pairs=[['compSearch','compTable'],['failSearch','failTable'],['allSearch','allTable']];
  for(var i=0;i<pairs.length;i++){
    var inp=document.getElementById(pairs[i][0]);
    if(inp) inp.value='';
    var rows=document.querySelectorAll('#'+pairs[i][1]+' tbody tr');
    for(var j=0;j<rows.length;j++) rows[j].style.display='';
  }
}

function clearSpotlight(){
  document.getElementById('spotlight-input').value='';
  document.getElementById('spotlight-results').style.display='none';
  document.getElementById('sp-cards').innerHTML='';
  clearAllTableFilters();
}

// Close spotlight when clicking anywhere outside the spotlight bar
document.addEventListener('click',function(e){
  var wrap=document.getElementById('spotlight-wrap');
  if(wrap && !wrap.contains(e.target)){
    document.getElementById('spotlight-results').style.display='none';
  }
});

</script>
</body>
</html>
"@


# ---------------------------------------------------------------------------
#  WRITE OUTPUT
# ---------------------------------------------------------------------------

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
    Write-Host "  [*] Created output folder: $OutputFolder" -ForegroundColor Green
}

$timestamp   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$modeTag     = if ($isMultiFile) { 'MultiRun' } else { 'SingleRun' }
$outFileName = "BHE-CompStatus-${modeTag}_${timestamp}.html"
$outPath     = Join-Path $OutputFolder $outFileName

$html | Out-File -FilePath $outPath -Encoding UTF8 -Force

Write-Host ''
Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Green
Write-Host '  |  Report written successfully                                |' -ForegroundColor Green
Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Green
Write-Host "     $outPath" -ForegroundColor White
Write-Host ''
Write-Host '  QUICK SUMMARY' -ForegroundColor Yellow
Write-Host "    Mode               : $modeLabel"
Write-Host "    Files analysed     : $($selectedFiles.Count)"
Write-Host "    Total rows         : $totalRows"
Write-Host "    Unique computers   : $uniqueComputers"
Write-Host "    Successful results : $($successRows.Count) ($pctSuccess%)"
Write-Host "    Failed results     : $($failRows.Count) ($pctFail%)"
Write-Host "    Not Active         : $($notActiveOnly.Count) computers"
Write-Host "    Task-level errors  : $($taskFailComputers.Count) computers"
Write-Host ''
Write-Host '  FAILURE BREAKDOWN' -ForegroundColor Yellow
foreach ($cg in $catGroups) {
    Write-Host ("    {0,-22} : {1}" -f $cg.Name, $cg.Count)
}
Write-Host ''
