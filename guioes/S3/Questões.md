## Questão 1: * Consegue observar diferenças no comportamento dos programas `otp.py` e `bad_otp.py`? Se sim, quais?

No otp.py, a função generate_random_bytes usa a função os.urandom para gerar bytes aleatórios. Esta função é considerada segura para fins criptográficos, pois gera números aleatórios a partir de fontes que são difíceis de prever.

Já no bad_otp.py, a função bad_prng usa a função random.randbytes para gerar bytes aleatórios. No entanto, antes de gerar os bytes, o gerador de números aleatórios é definido usando random.seed. Isto é inseguro, pois visto que se pode tornar previsível os números geraos, tornando os bytes gerados previsíveis também. Isso pode levar a vulnerabilidades na criptografia.

Portanto, a principal diferença entre os dois programas é que o otp.py é mais seguro para fins de criptografia do que bad_otp.py devido à maneira como eles geram os bytes aleatórios.

## Questão 2: * O ataque realizado no ponto anterior não entra em contradição com o resultado que estabelece a "segurança absoluta" da cifra *one-time pad*? Justifique.

Não, o ataque realizado no bad_otp_attack.py não entra em contradição com a “segurança absoluta” da cifra one-time pad. A segurança da desta é baseada em duas condições principais: a chave deve ser verdadeiramente aleatória e a chave deve ser usada apenas uma vez e depois descartada.

No caso do bad_otp_attack.py, a função bad_prng não é verdadeiramente aleatória. Ela usa uma "semente" que é previsível, tornando os bytes gerados também previsíveis. Isso viola a primeira condição da cifra otp. O programa otp.py usa a função os.urandom para gerar bytes aleatórios, que é considerada segura para fins criptográficos, pois gera números aleatórios a partir de fontes que são difíceis de prever.

Portanto, a falha de segurança no bad_otp_attack.py não é uma contradição da segurança da cifra otp, mas sim uma implementação incorreta da mesma visto esta ser segura quando bem implementada