<#################################################################
      Microsoft Windows Server 2012 R2 Hardening Benchmark
##################################################################>

$global:countIncorrect = 0
$global:flag = ""

# Create a log file for this process
$currentPath = Get-Location
$Date = Get-Date -UFormat %b-%m-%Y
$Hour = (Get-Date).Hour
new-item -Name 'output' -ItemType directory
$Log = "$($currentPath)\output\Microsoft_Windows_Server_2012R2-" + $Date + "-" + $Hour + ".log"

Start-Transcript -Path $Log -Force

# Enforce the script execution
function IsExecutionPolicyRestricted {
  $command = Get-ExecutionPolicy
  if ($command -ne "Unrestricted") {
    Set-ExecutionPolicy Unrestricted
  }
}

# Check if powershell has admin rights 
function IsAdministrator  {  
  $user = [Security.Principal.WindowsIdentity]::GetCurrent();
  (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}


function Get-RegistryKeyPropertiesAndValues {
  <#
    Description :
    This function accepts a registry path as parameter and returns all reg key properties and associated values
  #>
  Param([Parameter(Mandatory=$true)][string]$path)

  #List all the properties on the key path 
  try {
    Get-Item $path | ForEach-Object {Get-ItemProperty $_.pspath}
  } catch {write-host " Invalid path"}
} 

# Recuperate user's SID, used for the "HKEY_USERS" path
function Get-UserSID {

  $command = whoami

  $domain  = $command.Split("\") | select -First 1
  $user    = $command.Split("\") | select -Last 1
  $objUser = New-Object System.Security.Principal.NTAccount($domain, $user)
  $strSID  = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
    
  return $strSID.Value
}
     
# Check if a value is numeric
function IsNumeric ($Value) {
  return $Value -match "^[\d\.]+$"
}

# Extract int values from a string 
function Extract-NumbersFromString ([string]$inputString){
  $output = $inputString -replace("[^\d]")

  try{return [int]$output} catch{}
  try{return [uint64]$output} catch{return "NaN"}
}
 
function Check-ValueWithHardening {
  <#
    Description :
    This function compares the value of a property with the recommended one 
    by the CIS Windows Server 2012 R2 Hardening benchmark
  #> 
  Param([Parameter(Mandatory=$true)][string]$key,[string]$parameter,[string]$valueOfCIS)

  # List all the properties of the key path and grep the desired parameter 
  Get-Item $key | ForEach-Object {Get-ItemProperty $_.pspath} | findstr $parameter

  # Recuperate the value of the desired parameter
  try {  

    # Differenciate command line for Powershell version 4 or 5  
    if(($PSVersionTable.PSVersion).Major -eq 4) {
      $recuperatedValue = (Get-ItemProperty -Path $key).$parameter
    }
    if(($PSVersionTable.PSVersion).Major -eq 5) {
      $recuperatedValue = Get-ItemPropertyValue $key -Name $parameter
    }

    Write-host "recuperatedValue :" $recuperatedValue 
    Write-host "valueOfCIS :" $valueOfCIS 

  } catch {write-host " Invalid parameter"; return }
  
  
  ### Compare the value with CIS ###  
  # For an accurate numerical value
  if(IsNumeric($valueOfCIS)) {

    if ([int]$recuperatedValue -eq [int]$valueOfCIS) {
      Display-Correct "CORRECT"
    }
    
    else {
      Display-Correct "INCORRECT"
    }
  }

  # For an interval of values
  elseif($valueOfCIS.Contains("-")) {

    $inf = $valueOfCIS.Split("-") | select -First 1 
    $sup = $valueOfCIS.Split("-") | select -Last 1 

    if (($recuperatedValue -ge $inf) -And ($recuperatedValue -le $sup)) {
      write-host $inf "<=" $recuperatedValue "<=" $sup
      Display-Correct "CORRECT" 
    }

    else {
      write-host "Not" $inf "<=" $recuperatedValue "<=" $sup
      Display-Correct "INCORRECT"
    }    
  }

  # For a literal string value 
  else {Display-Correct "TO CHECK"}

 } 


  function Check-GPOValueWithHardening {
    <#
      Description :
      This function compares the GPO value of a property with the recommended one 
      by the CIS Windows Server 2012 R2 Hardening benchmark
    #> 
    Param([Parameter(Mandatory=$true)][string]$parameter,[string]$valueOfCIS)

    try {
      $result = Get-Content .\output\GPO_computer_result.txt | Select-String $parameter -Context 0,1

      $result = [string]$result 

      if ($result.Contains("Enabled") -Or $result.Contains("Activé")){
        $recuperatedValue = "Enabled"
      }
      elseif ($result.Contains("Disabled") -Or $result.Contains("Désactivé")){
        $recuperatedValue = "Disabled"
      }
      else {
        $recuperatedValue = Extract-NumbersFromString($result)
      }
      
      Write-host "recuperatedValue :" $recuperatedValue `t
      Write-host "valueOfCIS :" $valueOfCIS `t
    } catch{write-host " Invalid parameter"}

            
    if ([string]::IsNullOrEmpty($recuperatedValue)) {
      Display-Correct "EMPTY"
      return 
    }

    # For an interval of values 
    elseif($valueOfCIS.Contains('>=')) {
      $inf = $valueOfCIS.Split(">=") | select -Last 1 

      if ($recuperatedValue -ge $inf) {
        write-host $inf "<=" $recuperatedValue
        Display-Correct "CORRECT"
      }
      else {
        Display-Correct "INCORRECT"
      }
    }

    elseif($valueOfCIS.Contains("-")) {

      $inf = $valueOfCIS.Split("-") | select -First 1 
      $sup = $valueOfCIS.Split("-") | select -Last 1 

      if (($recuperatedValue -ge $inf) -And ($recuperatedValue -le $sup)) {
        write-host $inf "<=" $recuperatedValue "<=" $sup
        Display-Correct "CORRECT"
      }

      else {
        write-host $inf "<=" $recuperatedValue "<=" $sup
        Display-Correct "INCORRECT"
      }     
    }
    #For Enabled/Disabled strings 
    elseif($recuperatedValue -eq $valueOfCIS) {
      Display-Correct "CORRECT"
    }  
    
    else {
      Display-Correct "TO CHECK"
    } 
  }


# Display the flag CORRECT/INCORRECT/CHECK on the right side 
function Display-Correct($flag) {
  
  # Get the size of Powershell Window  
  $pshost = get-host
  $pswindow = $pshost.ui.rawui
  $sizeWindow = $pswindow.windowsize
    
  try {
    Write-host "[".PadLeft($sizeWindow.width-15) -ForegroundColor white -NoNewline;
  } catch {}
    

  if($flag -eq "CORRECT") {Write-host "CORRECT"  -ForegroundColor green -NoNewline; $global:flag = "CORRECT"}
  elseif($flag -eq "INCORRECT") {Write-host "INCORRECT"  -ForegroundColor red -NoNewline; $global:countIncorrect++; $global:flag = "INCORRECT"}
  elseif($flag -eq "TO CHECK") {Write-host "TO CHECK"  -ForegroundColor yellow -NoNewline; $global:flag = "TO CHECK"}
  else {Write-host "EMPTY"  -ForegroundColor white -NoNewline; $global:flag = "EMPTY"}

  Write-host "] `n`r" -ForegroundColor white;
}


function Format-Display ($value) {
  write-host " `n [+] " -NoNewline;
  write-host $value -ForegroundColor yellow 
  write-host "------------------------------"

  foreach ($k in $key) {   
    write-host "properties for $k"
    Get-RegistryKeyPropertiesAndValues -path $k   
  }
}

### Main script ###

if (-not (IsAdministrator)) {
  Write-Host "This script requires administrative rights, please run as administrator."
  exit
}

IsExecutionPolicyRestricted


$key =
'HKLM:\System\CurrentControlSet\Services\LanmanServer\',
'HKLM:\System\CurrentControlSet\Services\LanmanWorkStation\'

Format-Display("SMB Signing", $key)


Format-Display("Detect SMBv1", "")
Get-SmbServerConfiguration | Select EnableSMB1Protocol
### Disable SMBv1
#Set-SmbServerConfiguration -EnableSMB1Protocol $false


Format-Display("SCHANNEL Logging", 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL') 
Format-Display("KeyExchangeAlgorithms", 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\') 
Format-Display("Multi-Protocol", 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\') 
Format-Display("SSL & TLS", 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\')
Format-Display("Cipher Keys", 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\') 



function Read-Excel {

  Param([string]$filepath)
  Write-Host "File : " $filepath
  [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo] "en-US"

  # Open an existing Excel document
  $Excel = New-Object -ComObject excel.application 
  #Excel will be visible
  $Excel.visible = $True

  $Workbook = $excel.Workbooks.open($filepath) 
  $Worksheet = $Workbook.WorkSheets.item("sheet1") 
  $Worksheet.activate()

  # Recuperate numbers of rows and columns of Excel document
  $WorksheetRange = $workSheet.UsedRange
  $RowCount = $WorksheetRange.Rows.Count
  $ColumnCount = $WorksheetRange.Columns.Count
  Write-Host "RowCount:" $RowCount
  Write-Host "ColumnCount" $ColumnCount

  $line = 2

  # Display cells' content
  While ($line -le $RowCount) {

    $col = 2
    
    ### Stores all values of a same line of the excel document 
    # Description
    Write-Host $worksheet.Cells.Item($line,$col).Value() -ForegroundColor yellow 
    $col++

    # Recuperate key path
    $key = $worksheet.Cells.Item($line,$col).Value()
    $col++

    # Recuperate parameter (= name of property)
    $parameter = $worksheet.Cells.Item($line,$col).Value()
    $col++

    # Recuperate valueOfCIS (= the recommended value by the CIS Hardening Benchmark)
    $valueOfCIS = $worksheet.Cells.Item($line,$col).Value()
    $col++

    # DEBUG to check if parameters well-stored
    #write-host "key :" $key "parameter :" $parameter "valueOfCIS :" $valueOfCIS

    # Differenciate treatment between GPO and Key registry
    if ($key.Contains('GPO')) {
      try {
        # Compare the recuperated value of GPO with the recommended one by the CIS Hardening Benchmark
        Check-GPOValueWithHardening -parameter $parameter -valueOfCIS $valueOfCIS
      } catch {write-host "GPO Not Found `n"}  
    }

    # If path is not empty and valid 
    elseif ((-not ([string]::IsNullOrEmpty($key))) -And (Test-Path -Path $key)) {
      # Compare the recuperated value with the recommended one by the CIS Hardening Benchmark
      Check-ValueWithHardening -key $key -parameter $parameter -valueOfCIS $valueOfCIS
    } 

    else {write-host " Invalid keypath `n"; $global:flag = "INVALID"}

    # Complete the flag column
    $worksheet.Cells.Item($line,$col) = $global:flag
    
    # Reset at the first column for the next line
    $col=2

    # End of program, we close Excel
    if ($line -eq $RowCount){
      $workbook.Close()
      $excel.Quit()
      return
    }
   
    $line++
  } 
  Read-Host
}


# If Excel is no available on the target machine we try with csv format
function Test-Csv {

  Param([string]$filepath)
    # Store all values from CSV File in an array
    ForEach ($line in import-csv $filepath -Delimiter ';'){

      $array = @()

      $line = $line | Out-String

      ([String]$line).split("`r`n") |% { 
          # if current element not empty 
          if($_){
            if ($_.Contains('Key')) {
              if ($_.Contains("HKU")) {
                $userSID = Get-UserSID
                $element = "registry::HKEY_USERS\$($userSID)$($_.split("]")[1])";
              }
              else {
                $element = "$($_.split(":")[1]):$($_.split(":")[2])";
              }      
            }

            else {
              $element = $_.split(":")[1];
            }
              
            $array += $element | Out-String;
          }
      }

      ### DEBUG To display array 
      #$array | % { write-host $_}

      #Equivalent to : 
      <#foreach($element in $array){
      write-host $element;
      return
      }#>
  
      # You can access to object with index :
      $ID              = $array[0].Trim()
      $Description     = $array[1]
      $key             = $array[2].Trim()
      try{$parameter   = $array[3].Trim()} catch {}
      try{$valueOfCIS  = $array[4].Trim()} catch {}
      

      write-host " `n`r Description: " $Description -ForegroundColor yellow `t 
      write-host " ID:" $ID `t
      write-host " key: " $key `t
      
      #write-host "parameter: " $parameter "CIS recommended value: " $valueOfCIS

      # Differenciate treatment between GPO and Key registry
      if ($key.Contains("GPO")) {
        try {
          # Compare the recuperated value of GPO with the recommended one by the CIS Hardening Benchmark
          Check-GPOValueWithHardening -parameter $parameter -valueOfCIS $valueOfCIS
        } catch {write-host "GPO Not Found `n"}
      }

      # For path not empty and valid 
      elseif ((-not ([string]::IsNullOrEmpty($key))) -And (Test-Path -Path $key)) {
        # Compare the recuperated value with the recommended one by the CIS Hardening Benchmark
        Check-ValueWithHardening -key $key -parameter $parameter -valueOfCIS $valueOfCIS
      } 

      else {write-host " Invalid keypath `n"; $global:flag = "INVALID"}

    }
}



<#################################################################
    Create an HTML report for all Group Policy Objects (GPOs) in
    the local domain and two .txt for user and computer policies
##################################################################>


# gpedit.msc : to access the local group policy
# gpmc.msc : to access the domain group policy, installed by default on DC


#List all the policies applied to the computer
gpresult /Scope Computer /v  > .\output\GPO_computer_result.txt

# List all the policies applied to the user account you’re currently logged in with 
gpresult /Scope User /v > .\output\GPO_user_result.txt



# If machine is part of a domain 
if ((gwmi win32_computersystem).partofdomain -eq $true) {
 
 write-host -fore green "the machine $env:computername is well a member of domain. `n"
 Start-Sleep -s 2

 # Create HTML report for GPOs (run on the Domain Controller)
 Get-GPO -All | % {$_.GenerateReport('html') | Out-File ".\output\$($_.DisplayName).htm"}

 #List all empty GPOs
 foreach ($item in Get-GPO -All) {
  if ($item.Computer.DSVersion -eq 0 -and $item.User.DSVersion -eq 0) {
    write-host $item.DisplayName est vide !
  }
 }

} else {write-host -fore red "the machine $env:computername isn't a member of domain `n"; Start-Sleep -s 2}




try {
  Read-Excel -filepath "$($currentPath)\Windows_2012R2.xlsx"
} catch {
  write-host "Excel no available on the target machine, try with CVS file"
  Test-Csv -filepath "$($currentPath)\Windows_2012R2.csv"
}

Write-host "The script reveals : " $global:countIncorrect " incorrect values `n"

# Close log file
Stop-Transcript





# TO DO
function Generate-Report {

  Param([string]$filepath)
  Write-Host "File : " $filepath
  [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo] "en-US"

  # Open an existing Excel document
  $Excel = New-Object -ComObject excel.application 
  #Excel will be visible
  $Excel.visible = $False

  $Workbook = $excel.Workbooks.open($filepath) 
  $Worksheet = $Workbook.WorkSheets.item("sheet1") 
  $Worksheet.activate()

  # Recuperate numbers of rows and columns of Excel document
  $WorksheetRange = $workSheet.UsedRange
  $RowCount = $WorksheetRange.Rows.Count
  $ColumnCount = $WorksheetRange.Columns.Count
  Write-Host "RowCount:" $RowCount
  Write-Host "ColumnCount" $ColumnCount

  $line = 2

  # Display cells' content
  While ($line -le $RowCount) {

    $col = 6
    
    ### Stores all values of a same line of the excel document 
    $flag = $worksheet.Cells.Item($line,$col).Value()
    $col++

    if($flag -eq "INCORRECT"){
      Write-host "Description"
      Write-Host $worksheet.Cells.Item($line,$col).Value() 
      $col++

      Write-host "Rationale"
      Write-host $worksheet.Cells.Item($line,$col).Value()
      $col++

      Write-host "Remediation"
      Write-host $worksheet.Cells.Item($line,$col).Value()
      $col++

      Write-host "Impact"
      $valueOfCIS = $worksheet.Cells.Item($line,$col).Value()   
    }
   
    # Reset at the first column for the next line
    $col=2

    # End of program, we close Excel
    if ($line -eq $RowCount){
      $workbook.Close()
      $excel.Quit()
      return
    }
   
    $line++
  } 
  Read-Host
}
