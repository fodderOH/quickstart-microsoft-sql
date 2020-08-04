[CmdletBinding()]
param(

    [Parameter(Mandatory=$true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory=$true)]
    [string]$AdminSecret,

    [Parameter(Mandatory=$true)]
    [string]$SQLSecret,

    [Parameter(Mandatory=$true)]
    [string]$SeparateDataLogsVolume

)

# Getting Password from Secrets Manager for AD Admin User
$AdminUser = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $AdminSecret).SecretString
$SQLUser = ConvertFrom-Json -InputObject (Get-SECSecretValue -SecretId $SQLSecret).SecretString
# Getting the Name Tag of the Instance
$NameTag = (Get-EC2Tag -Filter @{ Name="resource-id";Values=(Invoke-RestMethod -Method Get -Uri http://169.254.169.254/latest/meta-data/instance-id)}| Where-Object { $_.Key -eq "Name" })
$NetBIOSName = $NameTag.Value

if ( $SeparateDataLogsVolume -eq "true" ) {
  ${SQLLogsDrive} = 'E'
}
else {
  ${SQLLogsDrive} = 'D'
}

try {
    Start-Transcript -Path C:\AWSQuickstart\Reconfigure-SQL.ps1.txt -Append
    $ErrorActionPreference = "Stop"

    [array]$paths = "D:\MSSQL\DATA","${SQLLogsDrive}:\MSSQL\LOG","F:\MSSQL\Backup","F:\MSSQL\TempDB"
    $sqlpath = (Resolve-Path 'C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\').Path
    $params = "-dD:\MSSQL\DATA\master.mdf;-e$sqlpath\MSSQL\Log\ERRORLOG;-l${SQLLogsDrive}:\MSSQL\LOG\mastlog.ldf"

    $DomainAdminFullUser = $DomainNetBIOSName + '\' + $AdminUser.UserName
    $DomainAdminSecurePassword = ConvertTo-SecureString $AdminUser.Password -AsPlainText -Force
    $DomainAdminCreds = New-Object System.Management.Automation.PSCredential($DomainAdminFullUser, $DomainAdminSecurePassword)

    $SQLFullUser = $DomainNetBIOSName + '\' + $SQLUser.UserName

    $ConfigureSqlPs={
        $ErrorActionPreference = "Stop"

        ForEach ($path in $Using:paths) {
            New-Item -ItemType directory -Path $path
            $rule = new-object System.Security.AccessControl.FileSystemAccessRule($Using:SQLFullUser,"FullControl",'ContainerInherit, ObjectInherit','InheritOnly',"Allow")
            $acl = Get-Acl $path
            $acl.SetAccessRule($rule)
            Set-ACL -Path $path -AclObject $acl
        }

        # Set Default Paths
        Import-Module SQLPS
        Set-Location "SQLSERVER:\SQL\$env:COMPUTERNAME\DEFAULT"
        $Server = (Get-Item .)
        $Server.DefaultFile = "D:\MSSQL\DATA"
        $Server.DefaultLog = "${SQLLogsDrive}:\MSSQL\LOG"
        $Server.BackupDirectory = "F:\MSSQL\Backup"
        $Server.Alter()

        # Update Startup settings with new master db path
        [System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement')| Out-Null
        $smowmi = New-Object Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer localhost
        $SQLService = $smowmi.Services | where {$_.name -eq 'MSSQLSERVER'}
        $SQLService.StartupParameters = $Using:params
        $SQLService.Alter()

        # Create account for SQL AD user
        Invoke-Sqlcmd -Query "CREATE LOGIN $Using:SQLFullUser FROM WINDOWS ;"
        Invoke-Sqlcmd -Query "ALTER SERVER ROLE [sysadmin] ADD MEMBER $Using:SQLFullUser ;"

        # Add Domain Admins as SQL SysAdmin
        Invoke-Sqlcmd -Query "CREATE LOGIN $Using:DomainAdminFullUser FROM WINDOWS ;"
        Invoke-Sqlcmd -Query "ALTER SERVER ROLE [sysadmin] ADD MEMBER $Using:DomainAdminFullUser ;"


        # Update paths for tempdb,model and MSDB
        Invoke-Sqlcmd -Query "USE master; ALTER DATABASE tempdb MODIFY FILE (NAME = tempdev, FILENAME = 'F:\MSSQL\TempDB\tempdb.mdf'); ALTER DATABASE tempdb MODIFY FILE (NAME = templog, FILENAME = 'F:\MSSQL\TempDB\templog.ldf');"
        Invoke-Sqlcmd -Query "USE master; ALTER DATABASE model MODIFY FILE (NAME = modeldev, FILENAME = 'D:\MSSQL\DATA\model.mdf'); ALTER DATABASE model MODIFY FILE (NAME = modellog, FILENAME = '${SQLLogsDrive}:\MSSQL\LOG\modellog.ldf');"
        Invoke-Sqlcmd -Query "USE master; ALTER DATABASE MSDB MODIFY FILE (NAME = MSDBData, FILENAME = 'D:\MSSQL\DATA\MSDBData.mdf'); ALTER DATABASE MSDB MODIFY FILE (NAME = MSDBLog, FILENAME = '${SQLLogsDrive}:\MSSQL\LOG\MSDBLog.ldf');"

        # Stop SQL Service
        $SQLService = Get-Service -Name 'MSSQLSERVER'
        if ($SQLService.status -eq 'Running') {$SQLService.Stop()}
        $SQLService.WaitForStatus('Stopped','00:01:00')

        # Move files to new locations
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\tempdb.mdf" "F:\MSSQL\TempDB\tempdb.mdf"
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\templog.ldf" "F:\MSSQL\TempDB\templog.ldf"
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\model.mdf" "D:\MSSQL\DATA\model.mdf"
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\modellog.ldf" "${SQLLogsDrive}:\MSSQL\LOG\modellog.ldf"
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\MSDBData.mdf" "D:\MSSQL\DATA\MSDBData.mdf"
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\MSDBLog.ldf" "${SQLLogsDrive}:\MSSQL\LOG\MSDBLog.ldf"
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\master.mdf" "D:\MSSQL\DATA\master.mdf"
        Move-Item "C:\Program Files\Microsoft SQL Server\MSSQL*.MSSQLSERVER\MSSQL\DATA\mastlog.ldf" "${SQLLogsDrive}:\MSSQL\LOG\mastlog.ldf"

        # Set SQL Server and Agent services user to SQL AD user
        $Services = Get-WmiObject -Class Win32_Service -Filter "Name='SQLSERVERAGENT' OR Name='MSSQLSERVER'"
        $Services.change($null,$null,$null,$null,$null,$null, $Using:SQLFullUser,$Using:SQLUser.Password,$null,$null,$null)

        # Start service
        $SQLService.Start()
        $SQLService.WaitForStatus('Running','00:01:00')
    }

    Invoke-Command -Authentication Credssp -Scriptblock $ConfigureSqlPs -ComputerName $NetBIOSName -Credential $DomainAdminCreds

}
catch {
    $raw = Get-Content -Path C:\AWSQuickstart\Reconfigure-SQL.ps1.txt -Raw
    Write-Host $raw
}
