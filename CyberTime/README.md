# Writeup

> Name : CyberTime
> 
> Category : web
> 
> Difficulty : easy
> 
> Description : CyberTime is a tool to convert a timestamp into comprehensible date
>
> URL : `http://<host>/`
> 

## English

- feedback system -> possibility to send stuff to an admin (XSS / CSRF)
- "robots.txt" -> allows to find the admin's dashboard
- in the dashboard sources -> file "dashboard.js"
- "dashboard.js" -> find the endpoint "/flag" and the endpoint "/admin/dashboard/add"
- "/admin/dashboard/add" -> we understand with the JS sources that the endpoint allows to transform a normal user into an administrator but you have to be an admin to use it
- "/flag" -> you have to be admin to see the flag
- send an URL like `http://<host>/admin/dashboard/add?username=<our_username>` to the admin via the feedback system
- the bot running to play the admin clicks on the links in the messages sent to it
- successful CSRF attack to get the admin role and access the flag

## Français

- système de feedback -> possibilité d'envoyer des trucs à un admin (XSS / CSRF)
- "robots.txt" -> permet de trouver le dashboard de l'admin
- dans les sources du dashboard -> fichier "dashboard.js"
- dashboard.js -> permet de trouver l'endpoint "/flag" et l'endpoint "/admin/dashboard/add"
- "/admin/dashboard/add" -> on comprend avec les sources JS que l'endpoint permet de transformer un utilisateur normal en administrateur mais il faut être admin pour pouvoir l'utiliser
- "/flag" -> il faut être admin pour voir le flag
- envoie d'une URL de la forme `http://<host>/admin/dashboard/add?username=<our_username>` à l'admin via le système de feedback
- le bot qui tourne pour jouer le rôle de l'admin clique sur les liens dans les messages qui lui sont envoyés
- attaque CSRF réussi pour pouvoir obtenir le rôle d'admin et accéder au flag
