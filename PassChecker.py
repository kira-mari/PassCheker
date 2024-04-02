import requests
import hashlib

def check_pwned_api(password):
    # Convertir le mot de passe en hash SHA1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    
    # Séparer le hash en préfixe et suffixe
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    # Faire la requête à l'API de pwnedpasswords
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    # Vérifier si la requête a réussi
    if response.status_code == 200:
        # Parcourir les réponses pour vérifier si le suffixe correspond
        for line in response.text.splitlines():
            pwned_suffix, count = line.split(':')
            if pwned_suffix == suffix:
                return int(count)
        # Si le suffixe n'est pas trouvé dans les réponses
        return 0
    else:
        # Gérer les erreurs de la requête
        print("La requête à l'API a échoué.")
        return None


def check_password(password):
    # Vérifier la longueur du mot de passe
    if len(password) < 8:
        return "Faible : Le mot de passe doit contenir au moins 8 caractères"
    
    # Vérifier la présence de différents types de caractères
    has_digit = any(char.isdigit() for char in password)
    has_alpha = any(char.isalpha() for char in password)
    has_special = any(not char.isalnum() for char in password)
    if not (has_digit and has_alpha and has_special) and len(password) > 10 :
        return "Moyen : Le mot de passe est long mais doit quand même contenir au moins un chiffre, une lettre et un caractère spécial"
    elif not (has_digit and has_alpha and has_special):
        return "Faible : Le mot de passe doit contenir au moins un chiffre, une lettre et un caractère spécial"
    
    # Vérifier les séquences à éviter
    sequences_a_eviter = [
        '123', 'abc', 'password', 'admin', 'qwerty', 'letmein', 'login', 'welcome',
        'football', 'monkey', 'abc123', 'starwars', '1234567890', 'dragon', 'master',
        'hello', 'freedom', 'whatever', 'shadow', 'trustno1', 'hunter', 'iloveyou',
        'sunshine', '1234', 'password1', 'qwerty123', 'welcome1', 'admin123', '123456',
        'passw0rd', 'football123', 'abcabc', '111111', '555555', '777777', '888888',
        '123qwe', '1qaz2wsx', 'adminadmin', 'password123', 'password1234', 'test123' ]
    for seq in sequences_a_eviter:
        if seq in password.lower():
            return "Faible : Le mot de passe contient une séquence à éviter"
    
    # Si le mot de passe passe toutes les vérifications
    return "Fort : Le mot de passe est robuste"


# Exemple d'utilisation
logo = """
    ____                  ________         __            
   / __ \____ ___________/ ____/ /_  ___  / /_____  _____
  / /_/ / __ `/ ___/ ___/ /   / __ \/ _ \/ //_/ _ \/ ___/
 / ____/ /_/ (__  |__  ) /___/ / / /  __/ ,< /  __/ /    
/_/    \__,_/____/____/\____/_/ /_/\___/_/|_|\___/_/     

Auteur : kira.mari
Version : 3.1415926535

"""
print(logo)
password = input("Entrez votre mot de passe à vérifier : ")
pwned_count = check_pwned_api(password)
if pwned_count is None:
    print("Erreur lors de la vérification du mot de passe.")
else:
    if pwned_count > 0:
        print(f"Le mot de passe a été compromis {pwned_count} fois.")
    else:
        print("Le mot de passe n'a pas été trouvé dans les bases de données de mots de passe compromis.")

result = check_password(password)
print(result)