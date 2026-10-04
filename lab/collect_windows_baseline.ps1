<#
.SYNOPSIS
    Collects a read-only Windows configuration baseline for a SIBERIAN lab run.
.DESCRIPTION
    Reads OS/build metadata, audit policy, Security log metadata/event counts,
    and NTFS USN journal metadata. It does not change policies, logs, journals,
    files, or network configuration. Collection failures are retained as errors;
    a failed query is never represented as an empty result.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string] $RunId,

    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory,

    [Parameter(Mandatory = $true)]
    [string] $IntervalStartUtc,

    [Parameter(Mandatory = $true)]
    [string] $IntervalEndUtc
)

$ErrorActionPreference = 'Stop'
$collectionStartedUtc = [DateTime]::UtcNow
$errors = [System.Collections.Generic.List[object]]::new()
$intervalStart = [DateTimeOffset]::Parse(
    $IntervalStartUtc,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal
).UtcDateTime
$intervalEnd = [DateTimeOffset]::Parse(
    $IntervalEndUtc,
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::AssumeUniversal
).UtcDateTime
if ($intervalStart -ge $intervalEnd) {
    throw 'IntervalStartUtc must be earlier than IntervalEndUtc.'
}

$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($outputRoot) | Out-Null
$outputFile = Join-Path $outputRoot "baseline-$RunId.json"
$temporaryFile = Join-Path $outputRoot "baseline-$RunId.$PID.tmp"
if ([IO.File]::Exists($outputFile)) {
    throw "Refusing to overwrite existing baseline: $outputFile"
}
if ([IO.File]::Exists($temporaryFile)) {
    throw "Refusing to overwrite an existing temporary report: $temporaryFile"
}

function Add-CollectionError {
    param([string] $Source, [string] $Message)
    $script:errors.Add([ordered]@{ source = $Source; message = $Message })
}

function Invoke-ReadOnlyNative {
    param([string] $Name, [string[]] $Arguments)
    try {
        $lines = @(& $Name @Arguments 2>&1 | ForEach-Object { "$_" })
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            Add-CollectionError -Source $Name -Message "Exit code $exitCode; output retained."
        }
        return [ordered]@{ exit_code = $exitCode; output = $lines }
    }
    catch {
        Add-CollectionError -Source $Name -Message $_.Exception.Message
        return [ordered]@{ exit_code = $null; output = @() }
    }
}

$os = $null
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
}
catch {
    Add-CollectionError -Source 'Win32_OperatingSystem' -Message $_.Exception.Message
}

$currentVersion = $null
try {
    $currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
}
catch {
    Add-CollectionError -Source 'Windows CurrentVersion registry key' -Message $_.Exception.Message
}

$volumes = @()
try {
    $volumes = @(Get-Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
        [ordered]@{
            drive_letter = [string]$_.DriveLetter
            filesystem = [string]$_.FileSystem
            filesystem_label = [string]$_.FileSystemLabel
            health_status = [string]$_.HealthStatus
            operational_status = @($_.OperationalStatus | ForEach-Object { [string]$_ })
        }
    })
}
catch {
    Add-CollectionError -Source 'Get-Volume' -Message $_.Exception.Message
}

$securityLog = $null
try {
    $log = Get-WinEvent -ListLog 'Security'
    $securityLog = [ordered]@{
        is_enabled = $log.IsEnabled
        record_count = $log.RecordCount
        log_mode = [string]$log.LogMode
        maximum_size_in_bytes = $log.MaximumSizeInBytes
        last_write_time_utc = if ($log.LastWriteTime) { $log.LastWriteTime.ToUniversalTime().ToString('o') } else { $null }
    }
}
catch {
    Add-CollectionError -Source 'Security event log metadata' -Message $_.Exception.Message
}

$eventCounts = [ordered]@{}
$eventQueryLimit = 100000
foreach ($eventId in @(4624, 4634, 4688, 5156)) {
    try {
        $eventRecords = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = $eventId
            StartTime = $intervalStart
            EndTime = $intervalEnd
        } -MaxEvents $eventQueryLimit -ErrorAction Stop)
        $wasCapped = $eventRecords.Count -ge $eventQueryLimit
        $eventCounts[[string]$eventId] = [ordered]@{
            status = if ($wasCapped) { 'count_capped' } else { 'queried' }
            count = $eventRecords.Count
            count_is_lower_bound = $wasCapped
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $eventCounts[[string]$eventId] = [ordered]@{
                status = 'queried'
                count = 0
                count_is_lower_bound = $false
            }
        }
        else {
            Add-CollectionError -Source "Security event $eventId query" -Message $_.Exception.Message
            $eventCounts[[string]$eventId] = [ordered]@{
                status = 'query_failed'
                count = $null
                count_is_lower_bound = $null
            }
        }
    }
}

$usnJournals = @()
foreach ($volume in $volumes | Where-Object { $_.filesystem -eq 'NTFS' }) {
    $drive = "$($volume.drive_letter):"
    $usnJournals += [ordered]@{
        drive = $drive
        query = Invoke-ReadOnlyNative -Name 'fsutil.exe' -Arguments @('usn', 'queryjournal', $drive)
    }
}

$auditPolicy = Invoke-ReadOnlyNative -Name 'auditpol.exe' -Arguments @('/get', '/category:*')
$securityLogConfig = Invoke-ReadOnlyNative -Name 'wevtutil.exe' -Arguments @('gl', 'Security')
$scriptHash = $null
try {
    $scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
catch {
    Add-CollectionError -Source 'lab script hash' -Message $_.Exception.Message
}

$report = [ordered]@{
    schema_version = 'siberian-lab-baseline-v1'
    run_id = $RunId
    collection_started_utc = $collectionStartedUtc.ToString('o')
    collection_finished_utc = [DateTime]::UtcNow.ToString('o')
    analysis_interval_utc = [ordered]@{
        start = $intervalStart.ToString('o')
        end = $intervalEnd.ToString('o')
    }
    collector = [ordered]@{
        script = 'collect_windows_baseline.ps1'
        script_sha256 = $scriptHash
        powershell_version = $PSVersionTable.PSVersion.ToString()
        identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        elevated = ([Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    platform = [ordered]@{
        computer_name = $env:COMPUTERNAME
        caption = if ($os) { $os.Caption } else { $null }
        version = if ($os) { $os.Version } else { $null }
        build_number = if ($os) { $os.BuildNumber } else { $null }
        architecture = if ($os) { $os.OSArchitecture } else { $null }
        edition_id = if ($currentVersion) { $currentVersion.EditionID } else { $null }
        display_version = if ($currentVersion) { $currentVersion.DisplayVersion } else { $null }
        ubr = if ($currentVersion) { $currentVersion.UBR } else { $null }
        product_name = if ($currentVersion) { $currentVersion.ProductName } else { $null }
    }
    volumes = $volumes
    audit_policy = $auditPolicy
    security_log_configuration = $securityLogConfig
    security_log_metadata = $securityLog
    security_event_counts = $eventCounts
    usn_journals = @($usnJournals)
    collection_errors = @($errors)
    interpretation = 'Inventory only. Counts do not establish event generation, completeness, absence, deletion, or intent.'
}

$json = $report | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText($temporaryFile, $json, [Text.UTF8Encoding]::new($false))
[IO.File]::Move($temporaryFile, $outputFile)
$writtenHash = (Get-FileHash -LiteralPath $outputFile -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "Baseline written: $outputFile"
Write-Output "SHA-256: $writtenHash"
if ($errors.Count -gt 0) {
    Write-Warning "Collection completed with $($errors.Count) error(s); inspect collection_errors in the report."
}
