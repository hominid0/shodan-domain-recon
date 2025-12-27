#!/usr/bin/env python3
"""
Reconocimiento de Subdominios en Shodan
Herramienta OSINT pasiva usando API Shodan para bug bounty.

Autor: Miguel Jiménez Cámara
Uso: Bug bounty & divulgación responsable
"""

import os
import sys
from datetime import datetime

# ========================================================
# Intentar importar shodan
try:
    import shodan
except ModuleNotFoundError:
    print("[!] Módulo 'shodan' no encontrado.")
    print("    1. Activa el entorno virtual: source venv/bin/activate")
    print("    2. Instala: pip install -r requirements.txt")
    sys.exit(1)

RESULTS_DIR = "results"

# --------------------------------------------------------
def banner():
    print("""
========================================================
 🔍 Reconocimiento Subdominios Shodan
 🇪🇸 OSINT Pasivo | Bug Bounty
========================================================
""")

# --------------------------------------------------------
def save(line, f):
    print(line)
    f.write(line + "\n")

# --------------------------------------------------------
def normalize_domain(domain):
    """Normaliza dominio: quita http(s) y barras"""
    domain = domain.strip().lower()
    domain = domain.replace("http://", "").replace("https://", "")
    return domain.rstrip("/")

# --------------------------------------------------------
def check_environment():
    """Verifica requisitos"""
    # Python 3.9+
    if sys.version_info < (3, 9):
        print("[!] Se requiere Python 3.9+")
        sys.exit(1)

    # SHODAN_API_KEY obligatoria
    if "SHODAN_API_KEY" not in os.environ:
        print("[!] SHODAN_API_KEY no encontrada")
        print("    export SHODAN_API_KEY='tu_clave'")
        sys.exit(1)

    # Crear directorio results
    os.makedirs(RESULTS_DIR, exist_ok=True)

# --------------------------------------------------------
def main(domain):
    check_environment()

    api_key = os.getenv("SHODAN_API_KEY")
    api = shodan.Shodan(api_key)

    domain = normalize_domain(domain)
    output_file = os.path.join(RESULTS_DIR, f"{domain}.txt")

    with open(output_file, "w", encoding="utf-8") as f:
        save(f"[+] Dominio objetivo: {domain}", f)
        save(f"[+] Timestamp: {datetime.utcnow()} UTC", f)
        save("=" * 80, f)

        # 1. SOLO Subdominios DNS Pasivos
        save("\n[1] Subdominios DNS Pasivos (Shodan)", f)
        save("=" * 80, f)
        
        try:
            dns_info = api.dns.domain_info(domain)
            subdomains = dns_info.get("subdomains", [])
        except shodan.APIError as e:
            save(f"[!] Error DNS: {e}", f)
            subdomains = []

        # Crear lista de URLs https://
        full_subdomains = sorted({f"https://{s}.{domain}" for s in subdomains})
        
        save(f"[+] Subdominios encontrados: {len(full_subdomains)}", f)
        for url in full_subdomains:
            save(f"{url}", f)

        save("\n[+] Reconocimiento completado.", f)
    
    print(f"\n[✔] Resultados guardados: {output_file}")

# --------------------------------------------------------
if __name__ == "__main__":
    banner()
    if len(sys.argv) != 2:
        print("Uso: python shodan_domain_recon.py example.com")
        sys.exit(1)
    main(sys.argv[1])
