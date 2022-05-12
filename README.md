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
