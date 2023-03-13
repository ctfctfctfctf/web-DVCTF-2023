# Writeup

## English

- The website was built with the Astro web framework (https://astro.build/) which allows to create static websites.
- It turns out that the framework offers functionalities to make the site non-static with SSR (Server Side Rendering) / https://docs.astro.build/en/guides/server-side-rendering/
- The adapter that was chosen to render the pages of the site is Deno: https://deno.land/. It is a kind of javascript sandbox. The sandbox is secure by default but it is possible to run it with additional permissions (https://deno.land/manual@v1.27.1/getting_started/permissions). It is then possible to escape from the sandbox via specific commands.
- The permissions used in the challenge are : 
    - `--allow-net=0.0.0.0:8085`
    - `--allow-read=/app/astro_web_chall/dist/client,/app/astro_web_chall/admin_password_954d3f72c784179a.txt`
    - `--allow-env`
- The vulnerable permission is `--allow-read` which allows to read files on the server (for instance the file with the admin password)
- To allow the user to execute javascript in the sandbox, the `eval()` function is used via one of the website's features
- The website also provides an admin interface that is only accessible with a password
- The admin interface contains the flag via a web page that cannot be brute-forced
- The vulnerable functionality is the one that transforms a colour name into a hexadecimal code
- The first payload `green;Deno.inspect(Deno.env.toObject())` retrieves the list of environment variables, the variable of interest is `npm_lifecycle_script`.
- The second payload `green;Deno.inspect(Deno.env.get('npm_lifecycle_script'))` retrieves the name of the file containing the admin password
- The third payload `green;Deno.inspect(Deno.readFileSync("admin_password_954d3f72c784179a.txt"))` retrieves the encoded admin password
- To decode it: [here](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Comma', false)&input=ODcsODAsNTUsNzIsNDksNTMsNDksNTMsNzcsODksNTIsNTMsNTUsMTE0LDQ4LDUyLDgwLDgwLDUyLDUzLDg3LDQ4LDExNCw2OCw1NCw1Miw1MCw1NSw0OSw1MCw1Nyw1Miw1NCw0OCw1Nyw1Miw1NSw1Niw1MQ)
- Admin password: `WP7H1515MY457r04PPP455W0rD642712946094783`
- Then you can connect to the admin interface via: `http://<host>/admin`
- And access the page containing the flag: `http://<host>/d1c30991da3141cc96d15f80123c1424`
- Get the flag ;)

## Français

- Le site a été construit avec le framework web Astro (https://astro.build/) qui permet de créer des sites statiques.
- Il se trouve que le framework propose des fonctionnalités pour rendre le site non statique avec du SSR (Server Side Rendering) / https://docs.astro.build/en/guides/server-side-rendering/
- L'adapteur qui a été choisi pour rendre les pages du site est Deno : https://deno.land/. C'est une sorte de sandbox javascript. La sandbox est sécurisée par défault mais il est possible de l'exécuter avec des permissions supplémentaires (https://deno.land/manual@v1.27.1/getting_started/permissions). Il est alors possible de s'échapper de la sandbox via des commandes spécifiques.
- Les permissions utilisées dans le challenge sont : 
    - `--allow-net=0.0.0.0:8085`
    - `--allow-read=/app/astro_web_chall/admin_password_954d3f72c784179a.txt,/app/astro_web_chall/dist/client/favicon.ico`
    - `--allow-env`
- La permission vulnérable est `--allow-read` qui permet de lire les fichiers sur le serveur, ici le fichier contenant le mot de passe de l'admin
- Pour que l'utilisateur puisse exécuter du javascript dans la sandbox, la fonction `eval()` est utilisée via l'une des fonctionnalités du site
- Le site propose aussi une interface admin accessible uniquement avec un mot de passe
- L'interface admin contient le flag via une page web impossible à brute-forcer
- La fonctionnalité vulnérable est celle qui transforme un nom de couleur en code hexadécimal
- Le premier payload `green;Deno.inspect(Deno.env.toObject())` permet de récupérer la liste des variables d'environnement, la variable qui nous intéresse est `npm_lifecycle_script`.
- Le second payload `green;Deno.inspect(Deno.env.get('npm_lifecycle_script'))` permet de récupérer le nom du fichier contenant le mot de passe de l'admin
- Le troisième payload `green;Deno.inspect(Deno.readFileSync("admin_password_954d3f72c784179a.txt"))` permet de récupérer le mot de passe de l'admin encodé
- Pour le décoder : [ici](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Comma', false)&input=ODcsODAsNTUsNzIsNDksNTMsNDksNTMsNzcsODksNTIsNTMsNTUsMTE0LDQ4LDUyLDgwLDgwLDUyLDUzLDg3LDQ4LDExNCw2OCw1NCw1Miw1MCw1NSw0OSw1MCw1Nyw1Miw1NCw0OCw1Nyw1Miw1NSw1Niw1MQ)
- Mot de passe de l'admin : `WP7H1515MY457r04PPP455W0rD642712946094783`
- On peut ensuite se connecter à l'interface admin via : `http://<host>/admin`
- Et accéder à la page contenant le flag : `http://<host>/d1c30991da3141cc96d15f80123c1424`
- Get the flag ;)
