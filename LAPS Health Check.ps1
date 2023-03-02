# =========================================================================
# THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
#
# The code sample is provided AS IS without warranty of any kind.
# I further disclaims all implied warranties including, without 
# limitation, any implied warranties of merchantability or of fitness for a
# particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall
# I, its authors, or anyone else involved in the creation,
# production, or delivery of the script be liable for any damages whatsoever
# (including, without limitation, damages for loss of business profits,
# business interruption, loss of business information, or other pecuniary
# loss) arising out of  the use of or inability to use the sample or
# documentation, even if I has been advised of the possibility of
# such damages.
#
# *******************
# Author: Kamil Olah
# *******************
#=========================================================================

param(
[Switch]$SendMessage=$true
)
 
#Edit the following variable to specify the domain or OU to search (e.g. workstations or servers) 
$searchBase="dc=ko,dc=sk" 

#Specify exclusions for OUs which should be skipped, use distinguished name separated by | 
$exclusions = "OU=Domain Controllers,DC=KO,DC=SK|OU=ToBeDeleted,OU=KO,DC=KO,DC=SK|OU=Clusters,OU=KO,DC=KO,DC=SK" 
 
#Edit the following variable to specify the LDAP server to use. Using domain name will select any DC in the domain 
$Server="dc3.ko.sk" 
 
#Edit the following variable to specify the share to store the output. 
$fileshare="c:\temp" 
 
#Edit the following variable, if necessary, every computer which LAPS password expired yesterday will appear on expired list
$ts=[DateTime]::Now.AddDays(-1).ToFileTimeUtc().ToString() 
 
#LDAP queries for LAPS statistics 
if ($exclusions -eq "") {

    $Computers = Get-ADComputer -Filter * -Server $Server -SearchBase $searchBase -Properties 'canonicalname','lastlogontimestamp','pwdlastset','ms-Mcs-AdmPwdExpirationTime','OperatingSystem','Enabled' 
    }

else {
    $Computers = Get-ADComputer -Filter * -Server $Server -SearchBase $searchBase -Properties 'canonicalname','lastlogontimestamp','pwdlastset','ms-Mcs-AdmPwdExpirationTime','OperatingSystem','Enabled' | where {$_.DistinguishedName -notmatch $exclusions}
    }

$enrolledComputers = $Computers | where {$_.'ms-MCS-AdmPwdExpirationTime' -ne $null}
$nonEnrolledComputers = $Computers | where {$_.'ms-MCS-AdmPwdExpirationTime' -eq $null}
$expiredNotRefreshed = $Computers | where {$_.'ms-MCS-AdmPwdExpirationTime' -lt $ts -and $_.'ms-MCS-AdmPwdExpirationTime' -ne $null}

#Permission check 
# get the 'ms-Mcs-AdmPwd' Schema Guid 
Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -LDAPFilter "(schemaidguid=*)" -Properties LdapDisplayName,SchemaIdGuid | ForEach-Object {

if ($_.LdapDisplayName -eq 'ms-Mcs-AdmPwd' )
    { 
    $Schema_Guid = [GUID]$_.SchemaIdGuid
    }
} 
$Output = @()

# Get the ACL of each computer object
foreach ($computer in $enrolledComputers) {
$CompName = $computer.DistinguishedName
# Filter identities with ExtendedRight on the ms-Mcs-AdmPwd, All Extended Right / Full Control AND filter out the default well-known groups 
$IdentityRef = ((Get-Acl -path "AD:$CompName").access | Where {(($_.ActiveDirectoryRights -like "*ExtendedRight*"  -and ( ($_.ObjectType -eq $Schema_Guid) `
-or ( $_.ObjectType -eq '00000000-0000-0000-0000-000000000000') )) -or ($_.ActiveDirectoryRights -like "*GenericAll*") `
)}).IdentityReference 

$Obj = "" | Select Name,CanonicalName,LastLogon,PwdLastSet,LAPS_PWD,OperatingSystem,Enabled,Identity 
$obj.Name = $computer.Name
$obj.CanonicalName = $computer.CanonicalName
$obj.LastLogon = [datetime]::FromFileTime($computer.lastlogontimestamp).tostring("dd-MM-yyy")
$obj.PwdLastSet = [datetime]::FromFileTime($computer.pwdlastset).tostring("dd-MM-yyy")
$obj.LAPS_PWD = [datetime]::FromFileTime($computer.'ms-MCS-AdmPwdExpirationTime').tostring("dd-MM-yyy")
$obj.OperatingSystem = $computer.OperatingSystem
$obj.Enabled = $computer.Enabled
$obj.Identity = $IdentityRef

$Output += $Obj 
}

$PermissionReport = $output | select Name,CanonicalName,LastLogon,PwdLastSet,LAPS_PWD,OperatingSystem,Enabled, @{Name=’WhoCanReadLAPSPwd’;Expression={[string]::join(" ; ", ($_.Identity))}} 
 
#Write the LAPS information (summary and detail) to a temporary file in the previously specified share 
$Content=@"
COUNTS
------
Enrolled: $(($enrolledComputers | measure).Count)
Not enrolled: $(($nonEnrolledComputers | measure).Count)
Expired: $(($expiredNotRefreshed | measure).Count)

DETAILS
-------

NOT ENROLLED
------------
$($nonEnrolledComputers | ft 'Name','CanonicalName',@{l=’LastLogon’; e={[datetime]::FromFileTime($_.lastlogontimestamp).ToString("dd-MM-yyyy")}},@{l=’PwdLastSet’; e={[datetime]::FromFileTime($_.'pwdLastSet').ToString("dd-MM-yyyy") }},@{l=’LAPS_PWD’; e={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime').ToString("dd-MM-yyyy") }},OperatingSystem,Enabled | Out-String) 

EXPIRED
-------
$($expiredNotRefreshed | ft 'Name','CanonicalName',@{l=’LastLogon’; e={[datetime]::FromFileTime($_.lastlogontimestamp).ToString("dd-MM-yyyy")}},@{l=’PwdLastSet’; e={[datetime]::FromFileTime($_.'pwdLastSet').ToString("dd-MM-yyyy") }},@{l=’LAPS_PWD’; e={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime').ToString("dd-MM-yyyy") }},OperatingSystem, Enabled | Out-String)

ENROLLED
--------
$($PermissionReport | Format-Table | Out-String)
"@

#Export to file reports 
$FileDate = (Get-Date).tostring("dd-MM-yyyy-hh-mm-ss")             
$Filename=$Fileshare+'\'+$Filedate+'_LAPSReport.txt'

Add-Content -Value $Content -Path $Filename

$EnrolledCSV = $Fileshare+'\'+$Filedate+'_LAPS_Enrolled.csv'
$NonEnrolledCSV = $Fileshare+'\'+$Filedate+'_LAPS_Non_Enrolled.csv'
$ExpiredCSV = $Fileshare+'\'+$Filedate+'_LAPS_Expired.csv'

$PermissionReport | Export-Csv $EnrolledCSV -NoClobber -NoTypeInformation 
$nonEnrolledComputers | select 'Name','CanonicalName',@{l=’LastLogon’; e={[datetime]::FromFileTime($_.lastlogontimestamp).ToString("dd-MM-yyyy")}},@{l=’PwdLastSet’; e={[datetime]::FromFileTime($_.'pwdLastSet').ToString("dd-MM-yyyy") }},@{l=’LAPS_PWD’; e={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime').ToString("dd-MM-yyyy") }},OperatingSystem,Enabled | Export-Csv $NonEnrolledCSV -NoClobber -NoTypeInformation 
$expiredNotRefreshed | select 'Name','CanonicalName',@{l=’LastLogon’; e={[datetime]::FromFileTime($_.lastlogontimestamp).ToString("dd-MM-yyyy")}},@{l=’PwdLastSet’; e={[datetime]::FromFileTime($_.'pwdLastSet').ToString("dd-MM-yyyy") }},@{l=’LAPS_PWD’; e={[datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime').ToString("dd-MM-yyyy") }},OperatingSystem,Enabled | Export-Csv $ExpiredCSV -NoClobber -NoTypeInformation 


If ($SendMessage)
{ 
#Edit the variables below to specify the email addresses and SMTP server to use
$EmailFrom = 'lapshealth@ko.sk' 
$EmailTo='emailaddress@ko.sk' 
$today = Get-Date 
$EmailSubject = 'LAPS Health Report for ' + $today.ToShortDateString() 
$EmailBody=$Content
$smtpserver= "dc3.ko.sk"  

Send-MailMessage -Body $EmailBody -From $EmailFrom -To $EmailTo -Subject $EmailSubject -SmtpServer $smtpserver -Attachments $EnrolledCSV,$NonEnrolledCSV,$ExpiredCSV 
} 
