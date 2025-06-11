# Resposta das Questões

## QUESTÃO 1: * Qual o impacto de executar o programa chacha20_int_attck.py sobre um criptograma produzido por pbenc_chacha20_poly1305.py? Justifique.

Um criptograma produzido por pbenc_chacha20_poly1305.py é uma combinação de dois algoritmos separados, a ChaCha20, uma cifra de fluxo usada para criptografar os dados e a Poly1305, um MAC, concebendo assim confidencialidade e integridade. 
Se usassemos um ataque tal como o desenvolvido pelo programa chacha20_int_attck.py sobre um criptograma daquele tipo, este não funcionaria diretamente. Em primeiro lugar a ChaCha20poly1305 usa uma nonce de 96 bits, ao contrário da ChaCha20 pura, que utiliza apenas 64 bits. O ataque da ChaCha20 não consegue adivinhar os 32 bits adicionais usados pelo Poly1305. 
Existe também o facto da Poly1305 fornecer autenticação para os dados criptografados. Assim, ao atacar o criptograma e tentar modificá-lo para adivinhar o nonce, a Poly1305 detetará a modificação e invalidará o criptograma.

## QUESTÃO 2: *Qual o motivo da sugestão de usar m2 com mais de 16 byte? Será possível contornar essa limitação?

Usar uma mensagem m2 com mais de 16 bytes serve para garantir que o ataque de extensão de comprimento no CBC-MAC não seja bem-sucedido. 
Se a mensagem original for menor que 16 bytes, essa limitação poderá ser explorada de modo a modificar o cyphertext sem modificar a tag. 
Para contornar esta limitação, podemos usar um MAC diferente ou aumentar o tamanho do bloco de criptografia.