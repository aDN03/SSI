# Projeto: Cofre Seguro
**Unidade Curricular:** Segurança de Sistemas Informáticos  
**Ano Letivo:** 2024/2025  
**Instituição:** Universidade do Minho  
**Autores:**  
Bento João Concieiro Guimarães A96296  
Flávio David Rodrigues Sousa A100715  
André Miguel Alves Carvalho A100818  
**Docente:** [Nome do professor]  

---

# Índice

1. [Introdução](#1-introdução)  
2. [Arquitetura do Sistema](#2-arquitetura-do-sistema)  
3. [Componentes Principais](#3-componentes-principais)  
   3.1 [Servidor](#31-servidor)  
   3.2 [Cliente](#32-cliente)  
   3.3 [Interface](#31-interface)  
   3.4 [Assistance](#32-assistance)  
4. [Segurança](#4-segurança)  
5. [Gestão de Grupos e Permissões](#5-gestão-de-grupos-e-permissões)  
6. [Design das Mensagens e Protocolo de Comunicação](#6-design-das-mensagens-e-protocolo-de-comunicação)  
7. [Testes e Demonstração](#7-testes-e-demostração)  
8. [Melhorias Implementadas](#8-melhorias-implementadas)  
9. [Limitações e Trabalho Futuro](#9-limitações-e-trabalho-futuro)  
10. [Conclusão](#10-conclusão)  

---

#   1. Introdução

No contexto da unidade curricular de Segurança de Sistemas Informáticos, o presente projeto tem como finalidade o desenvolvimento de um sistema seguro de armazenamento e partilha de ficheiros, designado por **Cofre Seguro**. Este sistema visa proporcionar aos utilizadores de uma organização a possibilidade de guardar e partilhar ficheiros de texto com garantias de **Autenticidade**, **Integridade** e **Confidencialidade**, pilares fundamentais da segurança da informação.

A solução proposta assenta numa arquitetura cliente-servidor, na qual os utilizadores interagem com a aplicação através de um cliente autenticado mediante certificados digitais X.509. A comunicação entre o cliente e o servidor é assegurada por um canal seguro, estabelecido através da troca de chaves Diffie-Hellman e cifrado com AES-GCM, impedindo a interceção ou modificação de dados por terceiros.

O projeto integra várias componentes de segurança estudadas ao longo do semestre, como a utilização de criptografia para proteção de dados (incluindo cifragem híbrida para partilha segura), autenticação mútua baseada em certificados, derivação de chaves, controlo de acessos, e partilha segura de informação em ambientes multiutilizador. Para além de cumprir os requisitos funcionais estabelecidos no enunciado, a implementação visa demonstrar a aplicação prática dos conceitos teóricos abordados, reforçando a importância da segurança na conceção de sistemas distribuídos.

Este relatório tem como objetivo expor detalhadamente a solução implementada, evidenciando como foram alcançados os objetivos propostos e, sobretudo, as estratégias adotadas para garantir os três pilares da segurança da informação mencionados anteriormente.


---

# 2. Arquitetura do Sistema

A solução é composta por quatro componentes principais:
- **Servidor**: Responsável por manter o estado da aplicação, gerir os cofres e responder aos pedidos dos clientes.
- **Cliente**: Aplicação com a qual o utilizador interage, autenticando-se com recurso a uma keystore e comunicando com o servidor através de uma ligação segura.
- **Interface**: Responsável por auxiliar o utilizador com o programa cliente.
- **Assistance**: Serve como uma biblioteca de suporte para autenticação com certificados digitais.

A comunicação entre cliente e servidor é estabelecida através de sockets com proteção criptográfica, garantindo que os dados trocados não podem ser lidos ou modificados por terceiros.

---

# 3. Componentes Principais

## 3.1 Servidor

- Mantém o estado dos cofres, utilizadores e grupos no sistema de ficheiros local.
- Controla o acesso aos ficheiros com base em permissões.
- Recebe comandos dos clientes, valida-os, executa operações e responde adequadamente.

## 3.2 Cliente

- Interpreta comandos do utilizador via terminal.
- Carrega a keystore PKCS12 para autenticação.
- Estabelece uma conexão segura com o servidor e envia os comandos definidos no enunciado (`add`, `list`, `share`, etc.).

## 3.3 Interface

- Apresenta ao utilizador as funcionalidades do programa.

## 3.4 Assistance

- Carregar credenciais
- Validar certificados e identidades
- Armazenar e recuperar certificados
- Gerar identificadores únicos para grupos

---

# 4. Segurança

A segurança do sistema “Cofre Seguro” assenta nos três pilares fundamentais da segurança da informação: **autenticidade**, **confidencialidade** e **integridade**, implementados através das seguintes técnicas e mecanismos:

## Autenticidade
- Cada cliente utiliza um **certificado digital X.509**, armazenado numa **keystore PKCS#12 (.p12)**, para se autenticar junto do servidor.
- O servidor valida o certificado do cliente contra uma **Autoridade Certificadora (CA)** interna confiável, garantindo que apenas utilizadores autorizados podem aceder ao sistema.
- A autenticação é realizada no início da ligação, com verificação do certificado e da chave privada correspondente.

## Confidencialidade
- Todos os ficheiros são cifrados no lado do cliente **antes** de serem enviados para o servidor, garantindo que o próprio servidor **não tem acesso ao conteúdo dos ficheiros**.
- A cifragem dos ficheiros é feita com uma **chave simétrica gerada aleatoriamente** (ex.: AES-256 em modo GCM).
- Esta chave é, por sua vez, **cifrada com a chave pública do(s) utilizador(es) autorizados** a aceder ao ficheiro (utilizando RSA ou semelhante).
- A comunicação entre cliente e servidor decorre sobre um canal seguro estabelecido através do protocolo de **troca de chaves Diffie-Hellman**, garantindo a confidencialidade e integridade dos dados trocados, mesmo na presença de terceiros.

## Integridade
- Cada ficheiro é cifrado utilizando o esquema **Fernet** (da biblioteca cryptography), que assegura não só a confidencialidade dos dados, mas também a sua integridade, recorrendo a **HMAC com SHA-256**. O cliente valida automaticamente se o ficheiro foi **alterado ou corrompido**, rejeitando conteúdos inválidos.

## Controlo de Acessos
- O sistema gere **permissões de leitura e escrita** por utilizador e por grupo.
- As permissões são verificadas antes de qualquer operação sensível (leitura, escrita, partilha).
- Cada grupo é associado a uma estrutura de chaves que garante que apenas membros autorizados conseguem decifrar os ficheiros partilhados nesse grupo.
---

# 5. Gestão de Grupos e Permissões

O sistema “Cofre Seguro” permite a criação e gestão de **grupos de utilizadores**, facilitando a partilha segura de ficheiros com diferentes níveis de permissões. Esta funcionalidade é essencial em ambientes colaborativos, onde diferentes utilizadores necessitam de aceder aos mesmos recursos com diferentes autorizações.

## Criação e Administração de Grupos
- Qualquer utilizador autenticado pode criar um novo grupo.
- O criador do grupo torna-se automaticamente o **administrador** desse grupo.
- O administrador pode:
  - Adicionar ou remover utilizadores do grupo.
  - Definir as **permissões** atribuídas a cada membro (leitura ou escrita).

## Permissões por Ficheiro
- Os ficheiros partilhados com grupos ou utilizadores podem ter permissões distintas:
  - **R (Read)**
  - **W (Write)**
- O sistema garante que apenas utilizadores com as permissões adequadas conseguem realizar a operação desejada.

- As permissões de leitura permitem ao utilizador ler ficheiros partilhados ou que fazem parte de um grupo através do comando _read_ 
- As permissões de leitura conferem a possibilidade de um utilizador apagar ou trocar (comandos _delete_ e _replace_, respetivamente) ficheiros partilhados consigo.
- No caso dos grupo as permissões de escrita, para além do _delete_ e _replace_ permitem ao utilizador adicionar novos ficheiros ao _vault_ do grupo

## Mapeamento de Permissões
- Cada ficheiro é associado a uma lista de utilizadores e/ou grupos com as respetivas permissões.
- Antes de qualquer operação (como leitura, substituição ou partilha), o servidor verifica se o utilizador tem autorização suficiente.

## Exemplo de Operações com Grupos
```bash
> group create EquipaX
> group add-user EquipaX VAULT_CLI2 W
> group add EquipaX documentos/plano.txt
```
---

##   6. Design das Mensagens e Protocolo de Comunicação

-   O protocolo de comunicação inicia-se com a troca de chaves Diffie-Hellman para estabelecer um segredo compartilhado.
-   A autenticação mútua é realizada com certificados X.509, onde o cliente e o servidor trocam certificados e assinam dados para verificar a identidade um do outro.
-   Após a autenticação, todas as mensagens são cifradas com AES-GCM utilizando uma chave derivada do segredo compartilhado.
-   As mensagens cifradas incluem um nonce e o texto cifrado, concatenados usando a função `mkpair` para delimitar os dados.
-   Os comandos são enviados em texto simples dentro das mensagens cifradas, seguidos por um separador ("?") e os argumentos do comando.
-   O servidor utiliza códigos de resposta (e.g., "1R", "404") para indicar o resultado das operações.
-   A transferência de ficheiros e outros dados é feita através das mensagens cifradas. Chaves de cifragem para partilha são cifradas com a chave pública do destinatário.
-   Estruturas de concatenação e separadores (e.g., ";") são usadas para transmitir dados mais complexos, como listas.

![ligação](/trabalho-pratico/images/ligação.png) \
<sup> **Figura 1: Estabelecer conexão** </sup>

![add](/trabalho-pratico/images/add.png) \
<sup> **Figura 2: Comando "add"** </sup>

![read](/trabalho-pratico/images/read.png) \
<sup> **Figura 3: Comando "read"** </sup>

![delete](/trabalho-pratico/images/delete.png) \
<sup> **Figura 4: Comando "delete"** </sup>

![share](/trabalho-pratico/images/share.png) \
<sup> **Figura 5: Comando "share"** </sup>

![revoke](/trabalho-pratico/images/revoke.png) \
<sup> **Figura 6: Comando "revoke"** </sup>

![list](/trabalho-pratico/images/list.png) \
<sup> **Figura 7: Comando "list"** </sup>

![replace](/trabalho-pratico/images/replace.png) \
<sup> **Figura 8: Comando "replace"** </sup>

![details](/trabalho-pratico/images/details.png) \
<sup> **Figura 9: Comando "details"** </sup>

![group create](/trabalho-pratico/images/group-create.png) \
<sup> **Figura 10: Comando "group create"** </sup>

![group delete](/trabalho-pratico/images/group-delete.png) \
<sup> **Figura 11: Comando "group delete"** </sup>

![group add-user](/trabalho-pratico/images/group-add-user.png) \
<sup> **Figura 12: Comando "group add-user"** </sup>

![group delete-user](/trabalho-pratico/images/group-delete-user.png) \
<sup> **Figura 13: Comando "group delete-user"** </sup>

![group add](/trabalho-pratico/images/group-add.png) \
<sup> **Figura 14: Comando "group add"** </sup>

![group list](/trabalho-pratico/images/group-list.png) \
<sup> **Figura 15: Comando "group list"** </sup>

---

# 7. Testes e Demonstração

Durante o desenvolvimento, a aplicação foi testada com diferentes utilizadores e comandos:

```
./client.py VAULT_CLI1.p12
> add documentos/segredo.txt
> list
> share file123 VAULT_CLI2 R
> group create EquipaX
> group add-user EquipaX VAULT_CLI2 W
> group add EquipaX documentos/plano.txt
> read file123
```

Os testes confirmaram a correta gestão de permissões, funcionamento dos comandos e a proteção da informação.

---

# 8. Melhorias Implementadas

-   **Comunicação com Criptografia:** Implementação de um canal de comunicação seguro utilizando o protocolo Diffie-Hellman para troca de chaves e AES-GCM para cifrar as mensagens trocadas entre cliente e servidor, garantindo a confidencialidade e integridade da comunicação.
-   **Autenticação Mútua:** Implementação de autenticação mútua entre cliente e servidor através de certificados digitais X.509, onde tanto o cliente quanto o servidor verificam a identidade um do outro antes de estabelecer a comunicação.
-   **Derivação de Chave:** Utilização da função de derivação de chave HKDF (HMAC-based Key Derivation Function) para derivar chaves de sessão a partir do segredo compartilhado estabelecido com o protocolo Diffie-Hellman, aumentando a segurança do sistema.
-   **Cifragem Assimétrica Híbrida:** Implementação de um sistema de cifragem híbrida onde as chaves simétricas usadas para cifrar os ficheiros são cifradas com a chave pública do(s) utilizador(es) autorizados (RSA com OAEP), permitindo partilha segura de ficheiros.
-   **Gestão de Permissões:** Implementação de um sistema de gestão de permissões que permite controlar o acesso aos ficheiros por utilizador, com permissões de leitura e escrita.
-   **Substituição Segura de Ficheiros:** Suporte para substituição segura de ficheiros, onde as permissões são validadas antes da operação de substituição.

- **Utilização de ficheiros json:** Foram utilizados ficheiros Json para guardar todo o tipo de informações relativas às permissões dos utilizadores de forma a ser mais fácil e mais rápido fazer verificações e alterações caso necessário.

- **Utilização de Fernet para cifragem simétrica segura:** Foi integrada a biblioteca cryptography com o esquema Fernet, que proporciona cifragem simétrica segura. Esta abordagem garante a confidencialidade e integridade  dos dados transmitidos entre cliente e servidor. O Fernet utiliza AES em modo CBC com uma chave de 128 bits e aplica HMAC com SHA-256 para detetar qualquer modificação nos dados cifrados. Assim, qualquer ficheiro corrompido ou alterado durante a transmissão é automaticamente rejeitado, reforçando a segurança geral do sistema.

---

# 9. Limitações e Trabalho Futuro

-   **Geração Dinâmica de Certificados:** O sistema atualmente depende de keystores pré-geradas. No futuro, pode ser implementada a geração dinâmica de certificados para simplificar o processo de gestão de identidades.
-   **Auditoria e Logs:** Criar um sistema de logs para ser possível observar todas as operações realizadas e o cliente responsável pela mesma. 
---

#   10. Conclusão

Este projeto permitiu aplicar conceitos fundamentais de segurança informática como criptografia (simétrica e assimétrica), troca de chaves Diffie-Hellman, autenticação mútua por certificado, derivação de chaves e controlo de acessos. A solução proposta cumpre os requisitos de segurança esperados, fornecendo um canal de comunicação seguro e um sistema robusto de armazenamento e partilha de ficheiros.

Embora o sistema já ofereça um alto nível de segurança, há áreas para melhorias futuras, como aprimorar o isolamento da lógica de controlo de acesso, implementar a geração dinâmica de certificados, otimizar a gestão de chaves, refinar o tratamento de erros, desenvolver uma interface gráfica e implementar testes automatizados. Estas melhorias podem aumentar ainda mais a segurança, a usabilidade e a robustez do sistema.

No geral, o projeto "Cofre Seguro" representa um avanço significativo na aplicação prática dos princípios de segurança em sistemas distribuídos e serve como uma base sólida para futuras extensões e desenvolvimentos.

---

