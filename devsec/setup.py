from .config import initialize

if __name__ == "__main__":
    created = initialize()
    print("Configuration créée." if created else "Configuration existante conservée.")
    print("Identifiants dans ACCESS_LOCAL.md (ne pas publier).")
