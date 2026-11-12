"""Create a local USER or ADMIN account in SQLite."""
import argparse, getpass
from server import create_user

def main():
    p=argparse.ArgumentParser(description="Створити обліковий запис локально")
    p.add_argument("username"); p.add_argument("--role",choices=("USER","ADMIN"),default="USER")
    a=p.parse_args(); password=getpass.getpass("Пароль (12+ символів): "); confirm=getpass.getpass("Повторіть пароль: ")
    if password != confirm: p.error("Паролі не збігаються")
    try: create_user(a.username,password,a.role)
    except Exception as exc: p.error(str(exc))
    print(f"Створено користувача з роллю {a.role}.")
if __name__=="__main__": main()
