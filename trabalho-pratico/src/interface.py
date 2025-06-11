import sys
import textwrap
from getpass import getpass


def display_welcome_banner(user_id):
    banner = f"""
    {'='*60}
    {' '*15}COFRE SEGURO - SSI VAULT SERVICE
    {'='*60}
    Utilizador: {user_id}
    Bem-vindo ao serviço de armazenamento seguro de ficheiros.
    
    Digite 'help' para ver os comandos disponíveis.
    Digite 'exit' para terminar a sessão.
    {'='*60}
    """
    print(textwrap.dedent(banner))


def display_help():
    help_text = """
    COMANDOS DISPONÍVEIS:
    
    GESTÃO DE FICHEIROS PESSOAIS:
      add <file-path>           - Adiciona o ficheiro ao cofre pessoal
      list [-u user-id | -g group-id] - Lista os ficheiros/grupos disponíveis
      share <file-id> <user-id> <permission> - Partilha o ficheiro (R/W)
      delete <file-id>          - Remove o ficheiro do sistema
      replace <file-id> <file-path> - Substitui o conteúdo do ficheiro
      details <file-id>         - Mostra os detalhes do ficheiro
      revoke <file-id> <user-id> - Revoga o acesso ao ficheiro
      read <file-id>            - Exibe o conteúdo do ficheiro
    
    GESTÃO DE GRUPOS:
      group create <group name> - Cria um novo grupo
      group delete <group-id>   - Elimina o grupo
      group add-user <group-id> <user-id> <permissions> - Adiciona um utilizador ao grupo
      group delete-user <group-id> <user-id> - Remove um utilizador do grupo
      group list                - Lista os grupos do utilizador
      group add <group-id> <file-path> - Adiciona um ficheiro ao grupo
    
    OUTROS:
      help                      - Mostra esta ajuda
      exit                      - Termina a sessão
    
    Exemplos:
      >> add documento.txt
      >> share doc123 user2 R
      >> group create equipa_projeto
    """
    print(textwrap.dedent(help_text))


def display_file_content(file_id, file_name, content):
    print(f"\nfile id: {file_id}")
    print(f"file name: {file_name}")
    print("content:")
    print("|", "-" * 40, "|")
    for line in content.split("\n"):
        print(f"|  {line.ljust(38)}  |")
    print("|", "-" * 40, "|\n")


def display_file_list(files, context="pessoal"):
    print(f"\nFicheiros no cofre {context}:")
    print("-" * 60)
    print("{:<15} {:<25} {:<15}".format("ID", "Nome", "Proprietário"))
    print("-" * 60)
    for file in files:
        print("{:<15} {:<25} {:<15}".format(file["id"], file["name"], file["owner"]))
    print()


def display_group_list(groups):
    print("\nGrupos do utilizador:")
    print("-" * 60)
    print("{:<15} {:<25} {:<15}".format("ID", "Nome", "Permissões"))
    print("-" * 60)
    for group in groups:
        print(
            "{:<15} {:<25} {:<15}".format(
                group["id"], group["name"], group["permissions"]
            )
        )
    print()


def display_file_details(file_info):
    print("\nDetalhes do ficheiro:")
    print("-" * 60)
    print(f"ID: {file_info['id']}")
    print(f"Nome: {file_info['name']}")
    print(f"Proprietário: {file_info['owner']}")
    print(f"Tamanho: {file_info['size']} bytes")
    print(f"Criado em: {file_info['created']}")
    print("\nUtilizadores com acesso:")
    print("-" * 30)
    for user, perm in file_info["shared_with"].items():
        print(f"{user}: {perm}")
    print("-" * 60 + "\n")
