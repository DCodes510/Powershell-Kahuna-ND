
###This is sample
Get-eventlog -logname system -newest 3

get-process -name notepad


####

Clear
$GetInitials = $null

do{
Clear
$Counter = 0
$FldrStructure = $null
Write-Host "

        "
Write-Host "Please input your Initials (example:  Rob Krane = RK)" -ForegroundColor Black -BackgroundColor Yellow
Write-Host "
"
$GetInitials = Read-Host 'What are your initials (example:  Rob Krane = RK)'
#$GetInitials
#Start-Sleep -Seconds 3
if ($GetInitials -eq "" -or $GetInitials -eq $null) {
    Write-Host "
    
            " -NoNewline
    Write-Host "You need to provide your initials" -ForegroundColor Yellow -BackgroundColor Black
    Write-Host "
    "
    #Start-Sleep -Seconds 1
    } #If no Initials Provided
else{
    $Counter = 0
    #$FldrStructure = "i"
    $ClassFiles = 'C:\ClassFiles-'
    $Folders = 'DayLabs','Export','Import','Samples'
    $Days = 1..5
    $TestPathClass = Test-Path -Path $ClassFiles$GetInitials -PathType Container
    #$TestPathClass
    #pause
    if ($TestPathClass -eq $false) {
        $FldrStructure = $FldrStructure + $ClassFiles
        New-Item -Path $ClassFiles$GetInitials -ItemType Directory
        } # If $TestPathClass $False
    foreach ($Folder in $Folders ) {
        $Folder
            $TestPathSub = Test-Path -Path $ClassFiles$GetInitials"\"$Folder -PathType Container
                if ($TestPathSub -eq $false) {
                    $Counter = $Counter + 1
                    $FldrStructure = $FldrStructure + 'S-'+$Folder+", "
                    New-Item -Path $ClassFiles$GetInitials\$Folder -ItemType Directory
                    } #If $Daylab
                 if ($Folder -eq 'Daylabs') {
                    #$Folder
                    foreach ($Day in $Days ) {
                    $Day
                        $TestPathDay = Test-Path -Path $ClassFiles$GetInitials"\"$Folder"\Day-"$Day -PathType Container
                        if ($TestPathDay -eq $false) {
                            $Counter = $Counter + 1
                            $FldrStructure = $FldrStructure + 'Day-'+$Day+", "
                            New-Item -Path $ClassFiles$GetInitials"\"$Folder"\Day-"$Day -ItemType Directory
                            #Start-Sleep -Milliseconds 500
                            } # TestpathDays $false
                        } # Foreach $Days   
            } # If $TestPathSub $false
        #Start-Sleep -Seconds 1
        } # foreach $Folders
    } # Initials provided
} # Do loop
While ($Counter -le -1 )

if ($Counter -eq 0) {
    Clear

    Write-Host "
    
                   " -NoNewline
    Write-Host $ClassFiles$GetInitials"  " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
    write-host "Structure Already Exists" -ForegroundColor Yellow -BackgroundColor Red
    Write-Host "
    
            "
    } # No folders created, structure exists

else {
    Clear

    Write-Host "
    
            " -NoNewline

    Write-Host $FldrStructure "Class Folder Structure Created" -ForegroundColor Black -BackgroundColor Green
    Write-Host "
    

            "
    } # One or more folders created

Pause

####





#5
#DO {doing part
    if (condition){
	    if (condition){doing part} #
	    elseif (condition){
		    if (condition){
			    foreach ($<item> in $<collection>){<statement list>}			
			    doing part
			    } #
		    elseif (condition){doing part} #
		    doing part
		    } #
	    doing part
	    }
    elseif (condition){
        foreach ($<item> in $<collection>){<statement list>}
        doing part
        }
    elseif (condition){doing part}
    elseif (condition){doing part}
    else {doing part}
#} 
#WHILE (condition)


$Folders = 'DayLabs','Export','Import','Samples'
$Days = 1..5

$Folders[2]

Get-Item -path C:\ClassFiles-ND\Export\exp_getproc-all-2.txt
Get-Item -path C:\ClassFiles-ND\Export\exp_getproc-all-2.txt | Select-Object -Property * | Out-GridView
$GetDocInfo = Get-Item -path C:\ClassFiles-ND\Export\exp_getproc-all-2.txt
$GetDocInfo | Select-Object -Property * | Out-GridView


$GetDocInfo.VersionInfo
$GetDocInfo.VersionInfo | Select-Object -Property * | Out-GridView
$GetDocInfo.VersionInfo.FileName
$GetDocInfo.Name



Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -Property * | Out-GridView
Get-WmiObject -Class Win32_Product | Select-Object -Property * | Out-GridView
$GetAppInfo = get-WmiObject -Class Win32_Product 
$GetAppInfo.properties
$GetAppInfo.properties
$GetAppInfo | Where-Object {$_.name -like "powershell 7*"}
$GetAppInfo | Where-Object {$_.name -like "powershell 7*"} | Select-Object -Property *
($GetAppInfo | Where-Object {$_.name -like "powershell 7*"}).properties | Select-Object -Property *
($GetAppInfo | Where-Object {$_.name -like "powershell 7*"}).properties | Select-Object -Property *

($GetAppInfo | Where-Object {$_.name -like "powershell 7*"}).properties.name
($GetAppInfo | Where-Object {$_.name -like "powershell 7*"}).properties
($GetAppInfo | Where-Object {$_.name -like "powershell 7*"}).properties | Where-Object {$_.name -like "Packagename"}
(($GetAppInfo | Where-Object {$_.name -like "powershell 7*"}).properties | Where-Object {$_.name -like "Packagename"}).value

Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object -Property * | Out-GridView

$GetAppInfo
write-host "$getappinfo"
Write-Host '$GetAppInfo'

####

exit
#Original Scenario from https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_foreach?view=powershell-5.1 
    $letterArray = "a","b","c","d"
    foreach ($letter1 in $letterArray)
    {
      Write-Host $letter1
      if ($letter1 -eq "B") {Write-host "This is 'B' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
      elseif ($letter1 -eq "d") {Write-host "This is 'd' elsif Statement " -BackgroundColor Black -ForegroundColor Yellow}

    }

#Scenario 1
$ArrayList = "notepad","CALCULATOR","Charmap"
$ArrayTable = Get-Process -Name $ArrayList
Write-Host '$Item is a single row [Array Table] from the $Collection [Array Table]. ' -BackgroundColor Black -ForegroundColor Yellow
foreach ($Item in $ArrayTable){
  Write-Host "
  "
  if ($Item.Name -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  elseif ($Item.Name -eq "Calculator") {Write-host "This is 'Calc' elsif Statement " -BackgroundColor Black -ForegroundColor Yellow}
Pause
}

#Scenario 2
$ArrayList = "notepad","Calculator","charmap"
$Items = Get-Process -Name $ArrayList
foreach ($Item in $Items){
  Write-Host $Item
  if ($Item -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  #if ($Item.Name -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  elseif ($Item.Name -eq "Calculator") {Write-host "This is 'Calc' elsif Statement " -BackgroundColor Black -ForegroundColor Yellow}
Pause
}



#Scenario 3
$ArrayList = "notepad","Calculator","charmap"
$getProc = Get-Process -Name $ArrayList
foreach ($GetIndividualProc in $getProc){
  Write-Host $GetIndividualProc.Name
  #if ($GetIndividualProc -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  #if ($GetIndividualProc.Name -eq "Notepad") {Write-host "This is" $GetIndividualProc.Name "IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
if ($GetIndividualProc.Name -eq "Notepad") {
    if ($GetIndividualProc.Id -ge 7000) {Write-host "     This ID" $GetIndividualProc.id "is equal or greater than 7000" -BackgroundColor Black -ForegroundColor Red }
    elseif ($GetIndividualProc.Id -le 6999 ) {Write-host "     This ID" $GetIndividualProc.id "is less than or equal to 6999" -BackgroundColor Black -ForegroundColor Red }
    Write-host "     This is" $GetIndividualProc.Name "IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
elseif ($GetIndividualProc.Name -eq "Calculator") {Write-host "     This is " $GetIndividualProc.Name " elsif Statement " -BackgroundColor Black -ForegroundColor Yellow}
#Scenario 2
$letterArray = "notepad","Calculator","charmap"
$Collection = Get-Process -Name $letterArray
foreach ($Item in $Collection){
  Write-Host $Item
  if ($Item -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  #if ($Item.Name -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  elseif ($Item.Name -eq "Calculator") {Write-host "This is 'Calc' elsif Statement " -BackgroundColor Black -ForegroundColor Yellow}
Pause
}

}

#Scenario 4
$ArrayList = "notepad","Calculator","charmap"
$getProcs = Get-Process -Name $ArrayList
foreach ($Proc in $getProcs){
  Write-Host $Proc.Name $Proc.Id
  $Proc| Select-Object -Property * | ft
  #if ($Proc -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  if ($Proc.Name -eq "Notepad") {Write-host "     This is" $Proc.id "IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
<#if ($Proc.Name -eq "Notepad") {
    if ($Proc.Id -ge 7000) {Write-host "This ID" $Proc.id "is equal or greater than 7000" -BackgroundColor Black -ForegroundColor Red }
    elseif ($Proc.Id -le 6999 ) {Write-host "This ID" $Proc.id "is less than or equal to 6999" -BackgroundColor Black -ForegroundColor Red }
    Write-host "This is" $Proc.Name "IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
elseif ($Proc.Name -eq "Calculator") {Write-host "This is " $Proc.Name " elsif Statement " -BackgroundColor Black -ForegroundColor Yellow}
#>
pause
}

#Scenario 5
$ArrayList = "notepad","Calculator","charmap"
$Procs = Get-Process -Name $ArrayList
foreach ($Proc in $Procs){
  Write-Host $Proc.Name
  #if ($Proc -eq "Notepad") {Write-host "This is 'Notepad' IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
  #if ($Proc.Name -eq "Notepad") {Write-host "This is" $Proc.Name "IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
if ($Proc.Name -eq "Notepad" -and $Proc.Id -ge 7000) {
    if ($Proc.Id -ge 10000) {Write-host "     This ID" $Proc.id "is equal or greater than 10000" -BackgroundColor Black -ForegroundColor Red }
    elseif ($Proc.Id -le 6999 ) {Write-host "     This ID" $Proc.id "is less than or equal to 6999" -BackgroundColor Black -ForegroundColor Red }
    Write-host "     This is" $Proc.Name "IF Statement " -BackgroundColor Black -ForegroundColor Yellow}
elseif ($Proc.Name -eq "Calculator") {Write-host "     This is " $Proc.Name " elsif Statement " -BackgroundColor Black -ForegroundColor Yellow}
#pause
}

#####




clear
$IMPTable = Import-Csv -Path C:\ClassFiles-ND\Export\exp_getproc-all.csv 
$IMPTable = Get-Content -Path C:\ClassFiles-ND\Export\exp_getproc-all.txt
$IMPTable = Get-Process 

$IMPTable
Get-Process | Get-Member #wil show you the CMDLet's list of "Member Types", no stored values for properties.
get-process | Select-Object -property * #will show 'command #1', all properties with stored values if there are any
get-process | Select-Object -property * | Out-GridView
get-process 
$IMPTable | Select-Object -property *
$IMPTable | Export-Csv -Path C:\ClassFiles-ND\Export\exp_getproc-all.csv -NoTypeInformation
$IMPTable | Out-File -FilePath C:\ClassFiles-ND\Export\exp_getproc-all-2.txt
$IMPTable | Select-Object -Property * | Out-File -FilePath C:\ClassFiles-ND\Export\exp_getproc-all-2.txt

$IMPTable.Count
$IMPTable[0]
$IMPTable[0].Name
$IMPTable.name 

$IMPTable[1]
$IMPTable[2]
$IMPTable[25]

$sample = $IMPTable[3]
$sample = $IMPTable | Where-Object {$IMPTable.name -eq "Notepad"} | Out-GridView
$sample = $IMPTable | Where-Object {$_.name -eq "Notepad"} #| Out-GridView

$IMPTable | Select-Object -Property * | Out-GridView
$IMPTable

$IMPTable.'PROCESS-1'
$IMPTable[0].'PROCESS-1'
$IMPTable[0].PROCESS-1
$IMPTable.server
$IMPTable[0.1].SERVER
$IMPTable[0,1]
$IMPTable[0,1].SERVER


$IMPTable[1.2]

####

# Scenario 1 (Based on About_Hashtable)
$hash = @{}
$hash = @{ Number = 1; Shape = "Square"; Color = "Blue"}

$hash
$hash.Keys
$hash.Values

$hash.Keys
$hash.Color
$hash["Time"] = "Now"

# Scenario 2
$p = @{"PowerShell" = (Get-Process PowerShell);
"Notepad" = (Get-Process notepad)}

$p
$p.Notepad
$p.Notepad.processname
$p.Notepad.processname

#$p.Add('ALL','Get-Process'  )
#$p.Add('ALL',Get-Process  )
$p.Add('ALL',(Get-Process)  )
$p.Keys
$p.Values
$p.ALL
$p.ALL.processname

$p.Remove('all')

#Scenario 3
$q = Get-Process # Array Table
$Folders = 'DayLabs','Export','Import','Samples' #Array list
$ProcList = Get-Content -Path C:\Class_Files-BK\Import\SelectProcList.txt

$Servers = 'LON-DC1','LON-SVR1','LON-CL1' #Array list
$hash1 = @{} # Framework of a hashtable
$hash1.Add('ALL',$q)
$hash1.ALL
$hash1.Add('Folders',$Folders)
$hash1.Remove('folders')
$hash1
$hash1.Folders
$hash1.Add('Servers',$Servers)
$hash1
$hash1.Servers
$hash1.Add('ProcessList',$ProcList)
$hash1
$hash1.ProcessList
$hash1 | Out-GridView
$hash1 | Export-Csv -Path C:\Class_Files-BK\Export\Hash1_Export.csv 
$hash1 | Export-Csv -Path C:\Class_Files-BK\Export\Hash1_Export-1.csv -NoTypeInformation



$hash1.Servers
$hash1.Folders
$hash1.ALL
$hash1.ALL | Select-Object -Property *
$GetProc | Where-Object {$_.ProcessName -eq $ProcListitem} | Export-Csv -Path C:\Class_Files-BK\Export\GetProc_SelectProc_AllProp.csv -NoTypeInformation -Append #-WhatIf
$hash1.ALL | Where-Object {$_.ProcessName -eq 'Notepad'} | Export-Csv -Path C:\Class_Files-BK\Export\GetProc_SelectProc_AllProp.csv -NoTypeInformation -Append #-WhatIf

foreach ( $processlist in $hash1.ProcessList){
    $hash1.ALL | Where-Object {$_.ProcessName -eq $processlist } | Export-Csv -Path C:\Class_Files-BK\Export\Hash1_SelectProcesses.csv -NoTypeInformation -Append #-WhatIf
    Write-Host $processlist
    Start-Sleep -Milliseconds 500

    }


$q.processname


#####

# 09.07.18/BK
# Version 2.1
# Display installed applications other than default ones
Invoke-Command -ScriptBlock {
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { #Office #Silverlight #Google Update Helper #7Zip #Adobe Reader DC and Refresh Manager #Chrome #Java
        $_.Caption -notlike 'Java*' -and $_.Caption -notlike 'Microsoft Office*' -and $_.Publisher -notlike 'Google*' -and $_.Publisher -notlike 'Oracle*' -and $_.Publisher -notlike 'Igor*' -and $_.DisplayName -notlike 'Adobe*' -and $_.DisplayName -notlike 'Update*' -and $_.InstallLocation -notlike '*Microsoft Office*' -and $_.ParentKeyName -notlike 'Office16*' -and $_.DisplayName -notlike '*silverlight*' -and $_.PSChildName -notlike 'Connection Manager' -and $_.PSChildName -notlike 'WIC'
        }
}

Invoke-Command -ScriptBlock {
Get-WmiObject -Class Win32_Product | Where-Object { #Office #Silverlight #Google Update Helper #7Zip #Adobe Reader DC and Refresh Manager #Chrome #Java
        #$_.identifyingnumber -eq {90160000-0090-0409-1000-0000000FF1CE}
        $_.identifyingnumber -notlike '{EECB2736-D013*}' -and $_.identifyingnumber -notlike '{90160000*}' -and $_.identifyingnumber -notlike '{89F4137D*}' -and $_.identifyingnumber -notlike '{60EC980A*}' -and $_.identifyingnumber -notlike '{23170F69*}' -and $_.identifyingnumber -notlike '{AC76BA86*}' -and $_.identifyingnumber -notlike '{30D6E9E5*}' -and $_.identifyingnumber -notlike '{26A24AE4*}' 
        }
}

Invoke-Command -ScriptBlock {
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { #Office #Silverlight #Google Update Helper #7Zip #Adobe Reader DC and Refresh Manager #Chrome #Java
        $_.Caption -notlike 'Java*' -and $_.Caption -notlike 'Microsoft Office*' -and $_.Publisher -notlike 'Google*' -and $_.Publisher -notlike 'Alex Feinman' -and $_.Publisher -notlike 'Conexant*' -and $_.Publisher -notlike 'NVIDIA*' -and $_.Publisher -notlike 'Oracle*' -and $_.Publisher -notlike 'Igor*' -and $_.DisplayName -notlike 'Update*' -and $_.InstallLocation -notlike '*Microsoft Office*' -and $_.ParentKeyName -notlike 'Office16*' -and $_.DisplayName -notlike '*silverlight*' -and $_.PSChildName -notlike 'Connection Manager' -and $_.PSChildName -notlike 'WIC'
        }
}
Pause

####

# Create scheduled task for Browser Favorite/Bookmark Backups
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass  -WindowStyle Minimized -File C:\NH\PS\Copy_Favorite-Bookmarks_to_OneDrive.ps1"  -WorkingDirectory "C:\NH\PS"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$trigger.Delay ='PT2M' 
$trigger.ExecutionTimeLimit = 'PT5M'
$principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Users" -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -ExecutionTimeLimit 5 -Priority 8 -StartWhenAvailable
$task = New-ScheduledTask -Description "Backup signed-in user's Edge Chromium Favorites and Google Chrome Bookmarks to their OneDrive" -Action $action -Principal $principal -Trigger $trigger -Settings $settings
Register-ScheduledTask -TaskName "BrowserFavorites_Backup" -InputObject $task -TaskPath \NH -Force

###








































#####get-date $startexport #2

$starttime = (get-date -Format 'MM-dd-yyyy hh:mm:ss')
$logfile = 'C:\ClassFiles-ND\Export\Logs\LogFile.txt'
$startexport = "Starting the process export procedure"
$endexport = "Finished the process export procedure"
$remoteserver = (Get-Adcomputer -Filter 'name -like "Lon-*"' -Properties operatingsystem | where-Object {$_.operatingsystem -like 'windows server*'}).dnshostname


$starttime+"  "+$startexport | Out-File -FilePath C:\ClassFiles-ND\Export\Logs\LogFile.txt -Append 
#pause
Get-Process -ComputerName $remoteserver | Select-Object -Property * | Export-Csv -Path C:\ClassFiles-ND\Export\getprocday2.csv -NoTypeInformation

#pause
$TestparthCSV = test-path -Path C:\ClassFiles-ND\Export\getprocday2.csv -PathType Leaf
if($TestparthCSV -eq $true){
    $starttime+"  "+$endexport | Out-File -FilePath $logfile -Append
    }

#pause










#####get-date $startexport #3

$starttime = (get-date -Format 'MM-dd-yyyy hh:mm:ss')
$logfile = 'C:\ClassFiles-ND\Export\Logs\LogFile.txt'
$startexport = "Starting the process export procedure"
$endexport = "Finished the process export procedure"
$remoteserver = (Get-Adcomputer -Filter 'name -like "Lon-*"' -Properties operatingsystem | where-Object {$_.operatingsystem -like 'windows server*'}).dnshostname


$starttime+"  "+$startexport | Out-File -FilePath C:\ClassFiles-ND\Export\Logs\LogFile.txt -Append 
#pause
Get-Process -ComputerName $remoteserver | Select-Object -Property * | Export-Csv -Path C:\ClassFiles-ND\Export\getprocday2.csv -NoTypeInformation

#pause
$TestparthCSV = test-path -Path C:\ClassFiles-ND\Export\getprocday2.csv -PathType Leaf
if($TestparthCSV -eq $true){
    $starttime+"  "+$endexport | Out-File -FilePath $logfile -Append
    }

#pause

####


# Revised 8.20.2021/BK
# Script to get ALL and select processes and show only ProcessName and ID on the local computer
# Version History
<#
    1.0 - New script to display processes and color coded values
    1.0.1- Output to a .CSV file ALL information
    1.1 - Select Processes to display
         - Select processes to output to .CSV
    1.1.1 - commented out start-sleep on line 28
    1.2 - dynamic file name for ALL and SELECT exports
        - Verification that file exported and met criteria for ALL and Select 
    1.2.1     1.3   - Add a menu system

Future Improvements or changes
    1.2.3 - Add additional criteria for Select processes


#>

:StartRM
Do {
$Rmval=0
# Declare Main Variables
$GetDate = Get-Date
$GetProc = Get-Process
$ProcDate = Get-Date -UFormat  %Y%m%d_%H%M%S   
$SelectPropInfo=$GetProc | Select-Object -Property ProcessName,Id
$ProcList= Get-Content -Path C:\ClassFiles\DayLabs\Source\ProcessList.txt
$ExpPath = 'C:\ClassFiles\DayLabs\Outputs'
$ExpSelFileNM = 'SelectProcessExport'
$ExpALLFileNM = 'AllProcessExport'
$ExpALLPath = $ExpPath + "\" + $ExpALLFileNM +"_"+ $ProcDate+"_" + $env:COMPUTERNAME+".csv"
$ExpSelPath = $ExpPath + "\" + $ExpSelFileNM +"_"+ $ProcDate+"_" + $env:COMPUTERNAME+".csv"

# Creating variable of select processes
$GetSelProc =@(
foreach($ProcItem1 in $ProcList ){
    $GetProc | Where-Object {$_.processname -eq $ProcItem1}
    #Start-Sleep -Milliseconds 1000
    }
    )

Clear

# Main Body
clear
Write-Host "



     " -NoNewline
Write-Host "What type of report would you like to see and export for Processes? " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
Write-host "(Full = 1, Select = 2) " -ForegroundColor Red -BackgroundColor Black -NoNewline
#Write-host "to GPUPDATE or type " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
Write-Host " QUIT = Q " -ForegroundColor Red -BackgroundColor Black -NoNewline
Write-Host " to end. " -ForegroundColor Yellow -BackgroundColor Black
Write-Host "

"

$inp= Read-Host " >" - # Type of report 

#  $inp
IF ($inp -eq "Q" ){Exit}  # If selection is QUIT
elseif(($inp -eq "1") -or ($inp -eq "2")  ){$Rmval=1}  # If selection is valid




if ($Rmval -eq 1){
    
# ALL Process Chosen    
    if ($inp -eq 1){
    
        # process for ALL
        Write-Host "


        "
        foreach($ProcListItem in $GetProc ){
            Write-Host "         " -NoNewline
            Write-Host $ProcListItem.ProcessName "  " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
            Write-Host $ProcListItem.Id -ForegroundColor Red -BackgroundColor Black
            #Start-Sleep -Milliseconds 100
            }

        Write-Host "

                Exporting ALL process data to a .CSV file..."

        $GetProc | Export-Csv -Path $ExpPath"\"$ExpALLFileNM"_"$ProcDate"_"$env:COMPUTERNAME".csv" -Force -NoTypeInformation #-WhatIf

        <# old method
        Write-Host "

                Export complete."
        #*Start-Sleep -Seconds 15
        #>

        if((Test-Path -Path $ExpALLPath -PathType Leaf).Equals($true)){
            #Get-ItemProperty -Path $ExpALLPath| Where-Object {$_.LastWriteTime -ge $GetDate -and $_.Length -ge 1000}
            if(Get-ItemProperty -Path $ExpALLPath| Where-Object {$_.LastWriteTime -ge $GetDate -and $_.Length -ne 0}){
              Write-Host "

                Export complete." -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                Start-Sleep -Seconds 3 # full script should have 15 seconds
          }
            else{
                Write-Host "File exists, but is not within the timeframe of being created during this script"  -ForegroundColor Yellow -BackgroundColor Black -NoNewline}
            }
        else{write-host "file does NOT exist"  -ForegroundColor Yellow -BackgroundColor Black -NoNewline}
    }    
    
# Select Process Chosen    
    elseif ($inp -eq 2){
    
    # processes for select
        Write-Host "


        "
        foreach($ProcListItem1 in $GetSelProc ){
            Write-Host "         " -NoNewline
            Write-Host $ProcListItem1.ProcessName "  " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
            Write-Host $ProcListItem1.Id -ForegroundColor Red -BackgroundColor Black
            #Start-Sleep -Milliseconds 100
            }

        Write-Host "

                Exporting Select process data to a .CSV file..."

        $GetSelProc | Export-Csv -Path $ExpPath"\"$ExpSelFileNM"_"$ProcDate"_"$env:COMPUTERNAME".csv" -Force -NoTypeInformation #-WhatIf

        <# old method
        Write-Host "

                Export complete."
        #*Start-Sleep -Seconds 15
        #>
        # validation of file export meeting conditions-Select
        if((Test-Path -Path $ExpSelPath -PathType Leaf).Equals($true)){
            #Get-ItemProperty -Path $ExpALLPath| Where-Object {$_.LastWriteTime -ge $GetDate -and $_.Length -ge 1000}
            if(Get-ItemProperty -Path $ExpSelPath| Where-Object {$_.LastWriteTime -ge $GetDate -and $_.Length -ne 0}){
              Write-Host "

                Export complete." -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                Start-Sleep -Seconds 3 # Return to 15 seconds.
          }
            else{
                Write-Host "File exists, but is not within the timeframe of being created during this script"  -ForegroundColor Yellow -BackgroundColor Black -NoNewline}
            }
        else{write-host "file does NOT exist"  -ForegroundColor Yellow -BackgroundColor Black -NoNewline}


    
            }    
    
    
    
            } # Valid selection 
else  # If Selection is NOT valid
{
            $Rmval=2
            Write-Host "
    
            " -NoNewline
            Write-Host " "$inp " " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
            Write-Host " is not a valid selection, press " -ForegroundColor Red -BackgroundColor Black -NoNewline
            Write-Host " ENTER " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
            Write-Host " to try again." -ForegroundColor Red -BackgroundColor Black
            Write-Host "
         "
            Pause
    }

} # do loop
while ($Rmval -ne $null)
# End of Script

#### day2


###time
on $(get-date -Format 'MM-dd-yyyy hh:mm:ss')

$starttime = get-date -Format 'MM-dd-yyyy hh:mm:ss'

(get-date -Format 'MM-dd-yyyy HH:mm:ss')+"  "+$startexport | Out-File -FilePath C:\ClassFiles-ND\Export\Logs\LogFile.txt -Append

$starttime+"  "+$startexport | Out-File -FilePath C:\ClassFiles-ND\Export\Logs\LogFile.txt -Append

Get-ADObject -LDAPFilter:"(anr=LON-)" -Properties:allowedChildClassesEffective,allowedChildClasses,lastKnownParent,sAMAccountType,systemFlags,userAccountControl,displayName,description,whenChanged,location,managedBy,memberOf,primaryGroupID,objectSid,msDS-User-Account-Control-Computed,sAMAccountName,lastLogonTimestamp,lastLogoff,mail,accountExpires,msDS-PhoneticCompanyName,msDS-PhoneticDepartment,msDS-PhoneticDisplayName,msDS-PhoneticFirstName,msDS-PhoneticLastName,pwdLastSet,operatingSystem,operatingSystemServicePack,operatingSystemVersion,telephoneNumber,physicalDeliveryOfficeName,department,company,manager,dNSHostName,groupType,c,l,employeeID,givenName,sn,title,st,postalCode,managedBy,userPrincipalName,isDeleted,msDS-PasswordSettingsPrecedence -ResultPageSize:"100" -ResultSetSize:"20201" -SearchBase:"DC=Adatum,DC=com" -SearchScope:"Subtree" -Server:"LON-DC1.Adatum.com"

Get-ADObject -LDAPFilter:"(objectClass=*)" -Properties:allowedChildClassesEffective,allowedChildClasses,lastKnownParent,sAMAccountType,systemFlags,userAccountControl,displayName,description,whenChanged,location,managedBy,memberOf,primaryGroupID,objectSid,msDS-User-Account-Control-Computed,sAMAccountName,lastLogonTimestamp,lastLogoff,mail,accountExpires,msDS-PhoneticCompanyName,msDS-PhoneticDepartment,msDS-PhoneticDisplayName,msDS-PhoneticFirstName,msDS-PhoneticLastName,pwdLastSet,operatingSystem,operatingSystemServicePack,operatingSystemVersion,telephoneNumber,physicalDeliveryOfficeName,department,company,manager,dNSHostName,groupType,c,l,employeeID,givenName,sn,title,st,postalCode,managedBy,userPrincipalName,isDeleted,msDS-PasswordSettingsPrecedence -ResultPageSize:"100" -ResultSetSize:"20201" -SearchBase:"CN=LON-CL10,CN=Computers,DC=Adatum,DC=com" -SearchScope:"Base" -Server:"LON-DC1.Adatum.com"

Get-ADComputer 
help Get-ADComputer -online

Get-Adcomputer -Filter 'name -like "Lon-*"' -Properties * | Select-Object -Property name,operatingsystem  | Out-GridView

(Get-Adcomputer -Filter 'name -like "Lon-*"')

$version = Get-Adcomputer -Filter 'name -like "Lon-*"' -Properties * 
$version | Select-Object -Property operatingsystem  | Out-GridView



help about_pssessions * -Online

Test-NetConnection -computername lon-svr1
Test-NetConnection -computername lon-svr1 -CommonTCPPort WINRM

help pssession
help about_pssessions -Online

new-pssession -ComputerName $remoteserver -name getproc
get-pssession

Invoke-Command -computername $remoteserver -ScriptBlock {get-process}
Invoke-Command -computername $remoteserver -ScriptBlock {get-process}
Get-Item

Invoke-Command -computername $remoteserver -ScriptBlock {
    Get-Item C:\
    }

Remove-PSSession -ComputerName $remoteserver

$remoteserver = (Get-Adcomputer -Filter 'name -like "Lon-*"' -Properties operatingsystem | where-Object {$_.operatingsystem -like 'windows server*'}).dnshostname

Invoke-Command -computername $remoteserver -ScriptBlock {
    Get-Item C:\
    }

Get-PSSession

#SMB (port# 445)

###


# Define the log file path
$LogFilePath = "C:\Logs\UserLogonActions.txt"

# Function to log activity
function Log-Activity {
    param ([string]$Message)
    $Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    $LogMessage = "$Timestamp - $Message"
    Add-Content -Path $LogFilePath -Value $LogMessage
}

# Log the user logon event
$UserName = $env:USERNAME
Log-Activity "User logged in: $UserName"

# Example: Track specific user actions (e.g., starting a process)
# Here you could add custom actions if needed
Write-Host "User logon logged successfully!"
