# PCTool1
multiple tools for intervention on PC


Menu du Script :

1.  Vérifications post masterisation
2.  Information Système
3.  Infos BitLocker
4.  Outils réseaux (ipconfig, tracert,...)
5.  Vérification GPO - gpresult
6.  Réactiver la carte Ethernet ou Wifi
7.  Visualiser la puissance du Signal Wifi
8.  Resynchroniser l'heure
9.  Désinstaller un logiciel
10. Journal d'évenement (erreur et critique)
  write-host "x.  Exit"


Certains résultats ne s'afficheront que si le script est lancé en administrateur, notamment pour BitLocker.
Voir également le script pour avoir quelques commentaires sur celui-ci.

Pour la désinstallation de logiciel, il peut y avoir des comportements différents, sur mon PC personnel, 
par exemple pour VLC la fenêtre de désinstallation s'affiche et il faut appuyer sur OK.

Sur les PC de mon organisation, il n' y a aucune fenêtre visible et cela désinstalle directement le soft en mode silencieux.


au choix "4 . outils réseaux (ipconfig, tracert,...)", dans le sous-menu "1. configuration réseau de l'interface active" ,
Il se peut que le résultat soit bizarre avec des informations manquantes. En effectuant la commande plusieurs fois le résultat devient cohérent.
résultat attendu :

InterfaceAlias       : Wi-Fi
InterfaceIndex       : 6
InterfaceDescription : Intel(R) Dual Band Wireless-AC 8260
NetProfile.Name      : "le nom de votre domaine"
IPv4Address          : "l'IP du PC"
IPv6DefaultGateway   :
IPv4DefaultGateway   : "IP de la passerelle"
DNSServer            : "IP du ou des DNS"
                       

Masque sous-réseaux  : 255.255.255.128 / CIDR: 25
Adresse MAC          : "Adresse MAC"
DHCP                 : Enabled


Screenshot :

![Capture1](https://user-images.githubusercontent.com/105367565/168375240-95613e70-06e3-4958-8fe8-073b3d9e991a.PNG)



