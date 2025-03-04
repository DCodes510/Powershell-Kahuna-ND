
Function get-CorpCompSysInfo {
    [cmdletbinding()]
    Param(
        [string[]]$ComputerName
        )
    
    ForEach($computer in $ComputerName)
        {
        $compsys = Get-CimInstance -ClassName win32_computersystem -ComputerName $Computer
        $bios = Get-CimInstance -ClassName win32_bios -ComputerName $Computer
        $properties = [ordered]@{
                        'Computername'  = $computer;
                        'BiosSerial'    = $bios.SerialNumber;
                        'Manufacturer'  = $compsys.Manufacturer;
                        'Model'         = $compsys.Model
                        }
                  $outputobject = New-Object -Typename psobject $properties
                  Write-Output $outputobject
     }
     }
    
     get-CorpCompSysInfo -ComputerName LON-SVR1, LON-DC1