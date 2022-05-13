  <#  

.NOTES
	NAME:	PCTool1.ps1
    VERSION : 1.0  17/04/2022
	AUTHOR:	Frédéric Puren



Certains résultats ne s'afficheront que si le script est lancé en administrateur, notamment pour BitLocker.
Voir également le script pour avoir quelques commentaires sur celui-ci.

Pour la désinstallation de logiciel, il peut y avoir des comportements différents, sur mon PC personnel, 
par exemple pour VLC la fenêtre de désinstallation s'affiche et il faut appuyer sur OK.

Sur les PC de mon organisation, il n' y a aucune fenêtre visible et cela désinstalle directement le soft en mode silencieux.

#>



# Décommenter les 6 lignes ci-dessous pour forcer le lancement du script en administrateur, sinon ouvrir powershell en administrateur et y lancer le script PCTool1.ps1


    If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}

  
  
  
  Do {
  
  
  write-host “################## MENU ###################” -ForegroundColor Blue
  Write-Host ""
  write-host “1.  Vérifications post masterisation” -ForegroundColor Cyan
  write-host "2.  Information Système" -ForegroundColor DarkCyan
  Write-Host "3.  Infos BitLocker" -ForegroundColor Cyan
  Write-Host "4.  Outils réseaux (ipconfig, tracert,...)" -ForegroundColor DarkCyan
  Write-Host "5.  Vérification GPO - gpresult" -ForegroundColor Cyan
  Write-Host "6.  Réactiver la carte Ethernet ou Wifi" -ForegroundColor DarkCyan
  write-host "7.  Visualiser la puissance du Signal Wifi" -ForegroundColor Cyan
  write-host "8.  Resynchroniser l'heure" -ForegroundColor DarkCyan
  Write-Host "9.  Désinstaller un logiciel" -ForegroundColor Cyan
  Write-Host "10. Journal d'évenement (erreur et critique)" -ForegroundColor DarkCyan
  Write-Host "11. Intégrer/Sortir un PC du domaine" -ForegroundColor Cyan
  write-host "x.  Exit" -ForegroundColor Red
  Write-Host ""
  write-host "###########################################" -ForegroundColor Blue
  Write-Host ""


  $choix = read-host “faire un choix”

  Write-Host ""


  switch ($choix){

  ######################################################################################
  # 1. Vérifications post masterisation”

    1{



Write-Host "-----------------------------------------" -ForegroundColor Magenta

# Nom du PC
write-host "Nom du PC :" -ForegroundColor Green
(gwmi WIN32_ComputerSystem).Name
Write-Host "-----------------------------------------" -ForegroundColor Magenta

# vérifier si le PC est bien sous un domaine ou WORKGROUP
write-host "Domaine :" -ForegroundColor Green
(gwmi WIN32_ComputerSystem).Domain
Write-Host "-----------------------------------------" -ForegroundColor Magenta

# status BitLocker sur C: (si le script n'est pas lancé en admin il y aura un message d'erreur "accès refusé...)
Write-Host "status BitLocker :" -ForegroundColor Green
Get-BitLockerVolume -MountPoint C| fl protectionStatus
Write-Host "-----------------------------------------" -ForegroundColor Magenta

# vérification si certains logiciels sont bien installés
Write-Host "vérification des logiciels installés :" -ForegroundColor Green
Write-Host ""


#exemple avec les logiciels suivants , à adapter suivant les logiciels que l'on veut vérifier.
$VLC = "VLC"
$chrome = "chrome"
$Machinchouette = "machinchouette"

# vérification des logiciels installés dans les 2 dossiers de registre suivants
$App32 = Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
$App64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

$Application32 = $App32 | Where-Object {![string]::IsNullOrWhiteSpace($_.DisplayName) } | Select-Object -ExpandProperty DisplayName -Unique
$Application64 = $App64 | Where-Object {![string]::IsNullOrWhiteSpace($_.DisplayName) } | Select-Object -ExpandProperty DisplayName -Unique


$versionVLC = $App64 | where DisplayName -match "VLC" | select -ExpandProperty DisplayVersion -ErrorAction SilentlyContinue
$VersionChrome = $App32 | where DisplayName -match "chrome" | select -ExpandProperty DisplayVersion -ErrorAction SilentlyContinue
$VersionMachinchouette = $App64 | where DisplayName -match "machinchouette" | select -ExpandProperty DisplayVersion -ErrorAction SilentlyContinue



   If (($Application32 -match $VLC) -or ($Application64 -match $VLC)){
    Write-Host "VLC est installé, version '$versionVLC'" -ForegroundColor Cyan
    } 
   else{
    Write-Host "VLC n'est pas installé" -ForegroundColor Red
    }

   If (($Application32 -match $chrome) -or ($Application64 -match $chrome)){
    Write-Host "Google chrome est installé, version '$VersionChrome'" -ForegroundColor Cyan
    } 
   else{
    Write-Host "Google Chrome n'est pas installé" -ForegroundColor Red
    }

   If (($Application32 -match $Machinchouette) -or ($Application64 -match $Machinchouette)){
    Write-Host "Machinchouette est installé, version '$VersionMachinchouette'" -ForegroundColor Cyan
    } 
   else{
    Write-Host "Machinchouette n'est pas installé" -ForegroundColor Red
    }


Write-Host "-----------------------------------------" -ForegroundColor Magenta


# vérifier les certificats personnels d'ordinateur installés

Write-Host "certificat(s) personnel(s) d'ordinateur installé(s) :" -ForegroundColor Green


Get-ChildItem -path cert:\LocalMachine\My | fl PSDrive, DnsNameList, NotBefore, NotAfter, Issuer



Write-Host "-----------------------------------------" -ForegroundColor Magenta


# version du BIOS
Write-Host "BIOS :" -ForegroundColor Green

Get-WmiObject win32_bios

write-host ""

Write-Host "#####################   FIN    ####################" -ForegroundColor Magenta


pause

Clear-Host
    
    }

##################################################################################################
# "2. Information Système"

    2{
    
    write-host "------------------------------------------------------" -ForegroundColor Magenta
    Write-Host "Modèle du PC :" -ForegroundColor Green
    Get-WmiObject Win32_ComputerSystem Model | select -Expandproperty Model
    write-host "------------------------------------------------------" -ForegroundColor Magenta
    write-host "Numéro de série du PC :" -ForegroundColor Green
    Get-WmiObject Win32_BIOS SerialNumber | select -expandproperty serialnumber
    write-host "------------------------------------------------------" -ForegroundColor Magenta
    write-host "Processeur :" -ForegroundColor Green
    Get-CimInstance -ClassName Win32_Processor | fl Name, Caption, MaxClockSpeed
    write-host "------------------------------------------------------" -ForegroundColor Magenta
    Write-Host "Mémoire RAM :" -ForegroundColor Green

    $BankLabelABool = [bool] (Get-CimInstance win32_physicalmemory | select BankLabel | where BankLabel -eq "ChannelA")
    $BankLabelB = Get-CimInstance win32_physicalmemory | select -Expandproperty BankLabel | where BankLabel -eq "ChannelB"
  

    Get-CimInstance win32_physicalmemory | Ft BankLabel, Speed, @{name="capacité (GB)";Expression={$_.Capacity/1GB}}

    if ($BankLabelBool -eq $true)
    {
    $RAMType = Get-CimInstance win32_physicalmemory | where BankLabel -eq "ChannelA" | select -ExpandProperty SMBIOSMemoryType

    if ($RAMType -eq 22)
    {
    write "Type de RAM : DDR2"
    }

    elseif ($RAMType -eq 24)
    {
    write "Type de RAM : DDR2-FB DIMM"
    }

    elseif ($RAMType -eq 25)
    {
    write "Type de RAM : DDR3"
    }

    elseif ($RAMType -eq 26)
    {
    write "Type de RAM : DDR4"
    }

    }

    else
    {
    $RAMType = Get-CimInstance win32_physicalmemory | where BankLabel -eq "ChannelB" | select -ExpandProperty SMBIOSMemoryType

    if ($RAMType -eq 22)
    {
    write "Type de RAM : DDR2"
    }

    elseif ($RAMType -eq 24)
    {
    write "Type de RAM : DDR2-FB DIMM"
    }

    elseif ($RAMType -eq 25)
    {
    write "Type de RAM : DDR3"
    }

    elseif ($RAMType -eq 26)
    {
    write "Type de RAM : DDR4"
    }

    }
    
    write-host ""

    write-host "------------------------------------------------------" -ForegroundColor Magenta
    Write-Host "Disque :" -ForegroundColor Green
    powershell Get-PhysicalDisk
    write-host "------------------------------------------------------" -ForegroundColor Magenta


    write-host ""

Write-Host "#####################   FIN    ####################" -ForegroundColor Magenta

    pause

Clear-Host

    }


####################################################################################################
# "3. Infos BitLocker"

    3{


    Do{

  
  write-host "1. voir le status de la protection" -ForegroundColor Cyan
  write-host “2. voir l'ID et MDP Bitlocker sur le PC” -ForegroundColor DarkCyan
  write-host “3. Faire remonter les infos BitLocker vers l'AD” -ForegroundColor Cyan
  write-host "x. exit" -ForegroundColor Red

  $choix = read-host “faire un choix”

  Write-Host ""
  Write-Host ""

  if ($choix -eq 1)
  {

manage-bde -status

    pause

    Clear-Host

    }

    elseif ($choix -eq 2)

    {

    manage-bde -protectors -get c:
    

        pause

    Clear-Host

    }


    elseif ($choix -eq 3)

    {

    $ADBegup = Get-BitLockerVolume -MountPoint "C:"
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $ADBegup.KeyProtector[1].KeyProtectorId

     

          pause

    Clear-Host

    }

}


    until ($choix -eq "x")


    Clear-Host

    powershell $PSCommandPath


    }

######################################################################################################
# "4. outils réseaux (ipconfig, tracert,..."

    4{

  write-host "1. configuration réseau de l'interface active" -ForegroundColor Cyan
  write-host “2. ipconfig /all” -ForegroundColor DarkCyan
  write-host "3. Tracert" -ForegroundColor Cyan
  write-host "4. Ping sur 1h - résultat dans un fichier .txt sur le bureau" -ForegroundColor DarkCyan
  write-host "5. Nslookup" -ForegroundColor Cyan
  write-Host "6. NetStat" -ForegroundColor DarkCyan
  write-host "x. exit" -ForegroundColor Red

  $choix = read-host “faire un choix”

  Write-Host ""
  Write-Host ""

    
    if ($choix -eq 1)
    {
    #interfaces actives
    $InterfaceUp = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*"} | select -ExpandProperty Name
    $MasqueCIDR = get-netipaddress | where {$_.interfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty PrefixLength
    $Mac = Get-netadapter -Name $InterfaceUp | select -ExpandProperty MacAddress
    $DHCP = Get-NetIPInterface | where {$_.InterfaceAlias -eq $InterfaceUp -and $_.AddressFamily -eq "IPv4"} | select -ExpandProperty Dhcp


    if ($MasqueCIDR -eq 0)
    {
    $Masque = "0.0.0.0"
    }

    if ($MasqueCIDR -eq 1)
    {
    $Masque = "128.0.0.0"
    }
    
    if ($MasqueCIDR -eq 2)
    {
    $Masque = "192.0.0.0"
    }
    
    if ($MasqueCIDR -eq 3)
    {
    $Masque = "224.0.0.0"
    }
    
    if ($MasqueCIDR -eq 4)
    {
    $Masque = "140.0.0.0"
    }
    
    if ($MasqueCIDR -eq 5)
    {
    $Masque = "148.0.0.0"
    }
    
    if ($MasqueCIDR -eq 6)
    {
    $Masque = "252.0.0.0"
    }
    
    if ($MasqueCIDR -eq 7)
    {
    $Masque = "254.0.0.0"
    }
 
    if ($MasqueCIDR -eq 8)
    {
    $Masque = "255.0.0.0"
    }

    if ($MasqueCIDR -eq 9)
    {
    $Masque = "255.128.0.0"
    }

    if ($MasqueCIDR -eq 10)
    {
    $Masque = "255.192.0.0"
    }

    if ($MasqueCIDR -eq 11)
    {
    $Masque = "255.224.0.0"
    }

    if ($MasqueCIDR -eq 12)
    {
    $Masque = "255.240.0.0"
    }

    if ($MasqueCIDR -eq 13)
    {
    $Masque = "255.248.0.0"
    }

    if ($MasqueCIDR -eq 14)
    {
    $Masque = "255.252.0.0"
    }

    if ($MasqueCIDR -eq 15)
    {
    $Masque = "255.254.0.0"
    }

    if ($MasqueCIDR -eq 16)
    {
    $Masque = "255.255.0.0"
    }

    if ($MasqueCIDR -eq 17)
    {
    $Masque = "255.255.128.0"
    }

    if ($MasqueCIDR -eq 18)
    {
    $Masque = "255.255.192.0"
    }

    if ($MasqueCIDR -eq 19)
    {
    $Masque = "255.255.224.0"
    }

    if ($MasqueCIDR -eq 20)
    {
    $Masque = "255.255.240.0"
    }

    if ($MasqueCIDR -eq 21)
    {
    $Masque = "255.255.248.0"
    }

    if ($MasqueCIDR -eq 22)
    {
    $Masque = "255.255.252.0"
    }

    if ($MasqueCIDR -eq 23)
    {
    $Masque = "255.255.254.0"
    }

    if ($MasqueCIDR -eq 24)
    {
    $Masque = "255.255.255.0"
    }

    if ($MasqueCIDR -eq 25)
    {
    $Masque = "255.255.255.128"
    }

    if ($MasqueCIDR -eq 26)
    {
    $Masque = "255.255.255.192"
    }

    if ($MasqueCIDR -eq 25)
    {
    $Masque = "255.255.255.128"
    }

    if ($MasqueCIDR -eq 26)
    {
    $Masque = "255.255.255.192"
    }

    if ($MasqueCIDR -eq 27)
    {
    $Masque = "255.255.255.224"
    }

    if ($MasqueCIDR -eq 28)
    {
    $Masque = "255.255.255.240"
    }

    if ($MasqueCIDR -eq 29)
    {
    $Masque = "255.255.255.248"
    }

    if ($MasqueCIDR -eq 30)
    {
    $Masque = "255.255.255.252"
    }

    if ($MasqueCIDR -eq 31)
    {
    $Masque = "255.255.255.254"
    }

    if ($MasqueCIDR -eq 32)
    {
    $Masque = "255.255.255.255"
    }


    Write-Host "Configuration IP actuelle :" -ForegroundColor Green

    Write-Host ""


    Get-NetIPConfiguration | where InterfaceAlias -eq $InterfaceUp


    write-host "Masque sous-réseaux  : $Masque / CIDR: $MasqueCIDR"

    
    Write-Host "Adresse MAC          : $Mac"

    
    Write-Host "DHCP                 : $DHCP"

    Write-Host ""
    Write-Host ""

    pause

    Clear-Host
    }


    elseif ($choix -eq 2)
    {
    #ipconfig \all
    ipconfig /all

    pause

    Clear-Host
    }

    elseif ($choix -eq 3)
    {
    #tracert
    $IP = read-host "adresse IP ou nom d'hôte cible"
    tracert $IP

    pause

    Clear-Host
    }


        elseif ($choix -eq 4)
    {
    $InterfaceUp = Get-NetAdapter | where {$_.status -like "Up" -and $_.Name -notlike "VMware*"} | select -ExpandProperty Name
    $Gateway = Get-NetIPConfiguration | where InterfaceAlias -eq $InterfaceUp | select -ExpandProperty IPv4DefaultGateway | select -ExpandProperty NextHop

    #Ping -t de la passerelle pendant 3600 echos (environ 1h) dans une autre fenetre cmd, résultat dans le fichier ping.txt sur le bureau.

    Start-Process cmd.exe "/c ping -n 3600 $Gateway > %userprofile%\Desktop\Ping.txt"

    pause

    Clear-Host
    }


    elseif ($choix -eq 5)
    {
    #NSlookup
    $IP = read-host "adresse IP ou nom d'hôte cible"
    nslookup $IP

    pause

    Clear-Host
    }


    elseif ($choix -eq 6)
    {
    #Netstat
    netstat -abno

    pause

    Clear-Host
    }


    elseif ($choix -eq "x")
    {
    Clear-Host

powershell $PSCommandPath
}

    }
######################################################################################################
# "5. Vérification GPO appliquées sur la session et le PC - gpresult"

    5{

    Do{

  write-host “1. gpresult_session - résultat dans le terminal” -ForegroundColor Cyan
  write-host "2. gpresult_session - résultat dans un fichier texte" -ForegroundColor Cyan
  write-host “3. gpresult_session - résultat dans un fichier html” -ForegroundColor Cyan
  write-host "4. gpresult_ordinateur - résultat dans le terminal" -ForegroundColor DarkCyan
  write-host “5. gpresult_ordinateur - résultat dans un fichier texte” -ForegroundColor DarkCyan
  write-host "6. gpresult_ordinateur - résultat dans un fichier html" -ForegroundColor DarkCyan
  write-host "x. exit" -ForegroundColor Red

  $choix = read-host “faire un choix”

  $Location = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition)

  if ($choix -eq 1)
  {
    gpresult /Z

    pause

    Clear-Host
    }

  elseif ($choix -eq 2)
  {
     gpresult /Z > $Location\gpresult_session.txt

    pause

    Clear-Host
    
    }


  elseif ($choix -eq 3)
  {
     gpresult /H $Location\gpresult_session.html

    pause

    Clear-Host
    
    }

     elseif ($choix -eq 4)
  {
     gpresult /Z /SCOPE computer

    pause

    Clear-Host
    
    }



     elseif ($choix -eq 5)
  {
     gpresult /SCOPE computer /Z > $Location\gpresult_ordinateur.txt

    pause

    Clear-Host
    
    }



     elseif ($choix -eq 6)
  {
     gpresult /H $Location\gpresult_ordinateur.html /SCOPE computer

    pause

    Clear-Host
    
    }

    }

    until ($choix -eq "x")


    Clear-Host

    powershell $PSCommandPath


    }


#####################################################################################################

# "6. Réactiver la carte Ethernet ou Wifi"


    6{

write-host "Status des cartes réseaux présentes :" -ForegroundColor Green

Get-NetAdapter | ft

Write-Host ""
Write-Host ""

write-host "Si une carte réseau physique est en status 'Disabled' ou 'Not Present' il faut la réactiver" -ForegroundColor Green

Write-Host ""
Write-Host ""

  write-host “1. Réactiver la carte Ethernet” -ForegroundColor Cyan
  write-host "2. Réactiver la carte Wifi" -ForegroundColor DarkCyan
  write-host "3. Réactiver une autre carte (ex Ethernet0, Ethernet1,etc.)" -ForegroundColor Cyan
  write-host "x. exit" -ForegroundColor Red

  Write-Host ""

  $choix = read-host “faire un choix”

  if ($choix -eq 1)
  {

    Enable-NetAdapter -Name Ethernet

    Write-Host ""

    Get-NetAdapter -Name Ethernet

    Write-Host ""

    pause

    Clear-Host
    }

  elseif ($choix -eq 2)
  {
    Enable-NetAdapter -Name Wi-Fi

    Write-Host ""

    Get-NetAdapter -Name Wi-Fi

    Write-Host ""

    pause

    Clear-Host
    
    }

    elseif ($choix -eq 3)
    {

    $Nom_Carte_Reseau = Read-Host "Tapez le nom de la carte à réactiver"

    Write-Host ""

    Enable-NetAdapter -Name $Nom_Carte_Reseau

    Write-Host ""

    Get-NetAdapter -Name $Nom_Carte_Reseau

    Write-Host ""

    pause

    Clear-Host
    
    }

    elseif ($choix -eq "x")
    {

    clear-host

    powershell $PSCommandPath
    }


    }

#######################################################################################################
# "7. Voir la puissance du Signal Wifi"

    7{

    write-host "Puissance du signal Wifi :" -Foregroundcolor Green

    Write-Host ""

    $Wifi = (netsh wlan show interfaces) -Match '^\s+Signal' -Replace '^\s+Signal\s+:\s+',''
    $wifi2 = $wifi -replace {%}

    if ($Wifi -lt "30%")
    {write-host $Wifi -ForegroundColor Red}


    elseif (($wifi -ge "30%") -and ($wifi -lt "50%"))
    {write-host $Wifi -ForegroundColor Magenta}
    
    elseif (($Wifi -ge "50%") -and ($Wifi -lt "70%"))
    {write-host $Wifi -ForegroundColor Blue}

    elseif ($Wifi -ge "70%")
    {write-host $Wifi -ForegroundColor Green}

    Write-Host ""

    pause

    Clear-Host
    }

#########################################################################################################
# "8. resynchroniser l'heure"

    8{
    powershell w32tm /resync /force

    pause

    Clear-Host
    }

##########################################################################################################
# "9. Désinstaller un logiciel"

    9{

write-host "Listes des logiciels installés :" -ForegroundColor Green

$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, UninstallString
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, UninstallString
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize


$Search = read-host "entrez le nom ou une partie du nom du logiciel à désinstaller"

$RESULT =$INSTALLED | ?{ $_.DisplayName -ne $null } | Where-Object {$_.DisplayName -match $Search } 

if ($RESULT.uninstallstring -like "msiexec*") {
$ARGS=(($RESULT.UninstallString -split ' ')[1] -replace '/I','/X ') + ' /q'
Start-Process msiexec.exe -ArgumentList $ARGS -Wait -Verbose
} 

else {
Start-Process $RESULT.UninstallString -Wait -Verbose
}


pause

Clear-Host

    
    }


#####################################################################################################
# "10. Journal d'évenement (erreur et critique)"

# 1 - Critique
# 2 - Erreur
# 3 - Avertissement
# 4 - Information

    10{

  write-host “1. log (erreur et erreur critique) du jour même” -ForegroundColor Cyan
  write-host "2. log (erreur et erreur critique) des 7 derniers jours - résultat dans un fichier texte" -ForegroundColor DarkCyan
  write-host "x. exit" -ForegroundColor Red
 

  $choix = read-host “faire un choix”

  if ($choix -eq 1)
  {

   $Date = (Get-Date).Adddays(-1)

Get-WinEvent Application, security, system | Where-Object {($_.Level -eq 1 -or $_.Level -eq 2) -and $_.TimeCreated -ge $Date}

    pause

Clear-Host

}

elseif ($choix -eq 2)
{   

   $Date = (Get-Date).Adddays(-7)

Get-WinEvent Application, security, system | Where-Object {($_.Level -eq 1 -or $_.Level -eq 2) -and $_.TimeCreated -ge $Date} | ft -Autosize | Out-File Erreur_Windows.txt

    pause

Clear-Host
}


elseif ($choix -eq "x")
{

Clear-Host

powershell $PSCommandPath
}

}

###########################################################################################################
# 11. Intégrer/Sortir un PC du Domaine


    11{

  write-host “1. Intégrer le PC au Domaine” -ForegroundColor Cyan
  write-host "2. Sortir le PC du domaine (en admin local)" -ForegroundColor DarkCyan
  Write-Host "x. exit" -ForegroundColor Red

  $choix = read-host “faire un choix”

  if ($choix -eq 1)
  {
  $Domaine = Read-host "entrer le nom du domaine à intégrer"


  Add-Computer -DomainName $Domaine

  
  pause

Clear-Host
  }

  elseif ($choix -eq 2)
  {

  $NomPC = hostname

  Remove-Computer -UnjoinDomainCredential $NomPC\Administrateur -Workgroup "workgroup" -Force

  
  pause

Clear-Host
  }

    elseif ($choix -eq "x")
  {

  Clear-Host
powershell $PSCommandPath
  }


  }


###########################################################################################################

    x{
    exit
    }


    }

    }
    until ($choix -eq "x")
