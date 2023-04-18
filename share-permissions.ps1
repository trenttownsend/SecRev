param(
  [string]$fileserver,
  [string]$share
)

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

if (-not $fileserver) {
  throw "Failed due to missing file server name."
}

if (-not $share) {
  throw "Failed due to missing share name."
}

$fileserver = $fileserver.Trim("`"'")

$shareData = @()

$share = $share.Trim("`"'")

$path = "\\$fileserver\$share"

# Get the share access information
$shareAccess = Get-SmbShare -Name $share -CimSession $fileserver | Get-SmbShareAccess
Write-Output "Share Access: $($shareAccess.Count) entries found."

# Get the NTFS permissions for subfolders in the share
Get-ChildItem -Recurse -Depth 0 "$path" | Where-Object { $_.PsIsContainer } | ForEach-Object { $path1 = $_.fullname; Get-Acl $_.Fullname | ForEach-Object { $shareData += $_.access | Add-Member -MemberType NoteProperty '.\Application Data' -Value $path1 -passthru }}

# Convert the array of custom objects to a CSV string and write it to the standard output
$shareDataCsv = $shareData | ConvertTo-Csv -NoTypeInformation
$shareAccessCsv = $shareAccess | ConvertTo-Csv -NoTypeInformation

Write-Output "###SHARE_ACCESS_START###"
Write-Output $shareAccessCsv
Write-Output "###SHARE_ACCESS_END###"

Write-Output "###SHARE_DATA_START###"
Write-Output $shareDataCsv
Write-Output "###SHARE_DATA_END###"