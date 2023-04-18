$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'

$Days = 30

$inactiveUsers = @()
$disabledUsers = @()

$AllUsers = Get-ADUser -Filter * -Properties *

foreach ($User in $AllUsers)
{
  $AttVar = Get-ADUser -Identity $User -Properties *
  if (($User.Enabled -eq $True) -and ($AttVar.LastLogonDate -lt ((Get-Date).AddDays(- $Days))))
  {
    $inactiveUsers += [PSCustomObject]@{
      'Name' = $User.Name
      'UserPrincipalName' = $User.UserPrincipalName
      'Last Logon' = $AttVar.LastLogonDate
    }
  }
  elseif (($User.Enabled -eq $True) -and  ($NULL -eq $User.LastLogonDate))
  {
    $neverlogged = "User has never logged on."

    $inactiveUsers += [PSCustomObject]@{
      'Name' = $User.Name
      'UserPrincipalName' = $User.UserPrincipalName
      'Last Logon' = $neverlogged
    }
  }

  if ($User.Enabled -eq $False) {
    $disabledUsers += [PSCustomObject]@{
      'Name' = $User.Name
      'UserPrincipalName' = $User.UserPrincipalName
    }
  }
}


$inactiveCsv = $inactiveUsers | Select-Object -Property Name,UserPrincipalName,'Last Logon' | ConvertTo-Csv -NoTypeInformation
Write-Output "###INACTIVE_USERS_START###"
Write-Output $inactiveCsv
Write-Output "###INACTIVE_USERS_END###"

$disabledCsv = $disabledUsers | Select-Object -Property Name,UserPrincipalName | ConvertTo-Csv -NoTypeInformation
Write-Output "###DISABLED_USERS_START###"
Write-Output $disabledCsv
Write-Output "###DISABLED_USERS_END###"


$groupMembers = @()

$Groups = Get-ADGroup -Filter * -Properties *

foreach ($Group in $Groups)
{
    $Users = (Get-ADGroupMember -Identity $Group | Sort-Object DisplayName | Select-Object -ExpandProperty Name) -join ", "
    $groupMembers += [PSCustomObject]@{
        'Name' = $Group.name
        'Members' = $Users
    }
}

$groupMembersCsv = $groupMembers | Select-Object -Property Name,Members | ConvertTo-Csv -NoTypeInformation
Write-Output "###GROUP_MEMBERS_START###"
Write-Output $groupMembersCsv
Write-Output "###GROUP_MEMBERS_END###"