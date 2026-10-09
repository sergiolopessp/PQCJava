# Post-Quantum Cryptography (PQC) Demo - Java 27 & AWS SDK

Demonstração prática de criptografia pós-quântica (PQC) utilizando as APIs nativas do **Java 27** baseadas nos padrões NIST (**FIPS 203** e **FIPS 204**), combinadas com serviços de nuvem da **AWS** (AWS KMS e AWS Secrets Manager via AWS SDK v2) simulados localmente com **Testcontainers** e **LocalStack Pro**.

---

## 📋 Sumário

- [Visão Geral dos Padrões PQC](#-visão-geral-dos-padrões-pqc)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Pré-requisitos](#-pré-requisitos)
- [Configuração do LocalStack Pro](#-configuração-do-localstack-pro)
- [Executando as Demonstrações](#-executando-as-demonstrações)
  - [1. Assinatura Digital com ML-DSA (FIPS 204)](#1-assinatura-digital-com-ml-dsa-fips-204)
  - [2. Troca de Chaves com ML-KEM (FIPS 203)](#2-troca-de-chaves-com-ml-kem-fips-203)
- [Executando os Testes de Integração (Testcontainers + LocalStack)](#-executando-os-testes-de-integração-testcontainers--localstack)
- [Cenários de Teste Implementados](#-cenários-de-teste-implementados)
- [Arquitetura de Segurança](#-arquitetura-de-segurança)

---

## 🔬 Visão Geral dos Padrões PQC

Com a iminência de computadores quânticos capazes de quebrar algoritmos assimétricos tradicionais (como RSA e curvas elípticas ECDSA/ECDH via algoritmo de Shor), o NIST padronizou novos algoritmos baseados em reticulados (*lattice-based cryptography*):

| Padrão | Algoritmo | Finalidade | Nível NIST / Segurança |
| :--- | :--- | :--- | :--- |
| **FIPS 203** | **ML-KEM** (Module-Lattice KEM / Kyber) | Mecanismo de Encapsulamento de Chave (KEM) para estabelecimento seguro de segredo compartilhado. | Parâmetros 512 (Nível 1), 768 (Nível 3) e 1024 (Nível 5). |
| **FIPS 204** | **ML-DSA** (Module-Lattice DSA / Dilithium) | Assinatura e verificação digital resistente a ataques quânticos. | Parâmetros 44 (Nível 2), 65 (Nível 3) e 87 (Nível 5). |

O Java 27 suporta ambos nativamente através do provider padrão `SunJCE` e das APIs `java.security.Signature`, `java.security.KeyPairGenerator` e `javax.crypto.KEM`.

---

## 📁 Estrutura do Projeto

```text
├── pom.xml                                  # Configurações do Maven, plugins e dependências (AWS SDK, JUnit 5, Testcontainers)
├── config.properties                        # Configurações locais (chave LocalStack Pro - ignorada no git)
├── .gitignore                               # Protege chaves, segredos e artefatos de compilação
└── src
    ├── main
    │   └── java
    │       └── com
    │           └── arquitetura
    │               └── pqc
    │                   ├── PostQuantumSignatureDemo.java    # Demo de assinatura digital ML-DSA-44
    │                   └── PostQuantumKeyExchangeDemo.java  # Demo de acordo de chaves ML-KEM-768
    └── test
        └── java
            └── com
                └── arquitetura
                    └── pqc
                        └── PostQuantumAwsIntegrationTest.java # Testes com AWS SDK, JUnit 5 e LocalStack
```

---

## ⚙️ Pré-requisitos

- **Java JDK 27** instalado (ex: Eclipse Adoptium / Temurin 27)
- **Apache Maven 3.9+**
- **Docker** ou **Docker Desktop** ativo

---

## 🔑 Configuração do LocalStack Pro

O projeto suporta o **LocalStack Pro** de forma transparente via arquivo de propriedades ou variável de ambiente.

1. No arquivo `config.properties` na raiz do projeto, insira seu token:
   ```properties
   localstack.auth.token=SEU_TOKEN_LOCALSTACK_PRO_AQUI
   ```

2. *(Opcional)* Se preferir definir via variável de ambiente no seu terminal:
   ```bash
   export LOCALSTACK_AUTH_TOKEN="SEU_TOKEN_LOCALSTACK_PRO_AQUI"
   ```

> 🔒 **Nota de Segurança:** O arquivo `config.properties` e arquivos `.env` já estão configurados no `.gitignore`, evitando vazamento acidental de credenciais no repositório. Caso nenhuma chave seja informada, os testes utilizam automaticamente a imagem comunitária `localstack/localstack:latest` como fallback.

---

## 🚀 Executando as Demonstrações

### 1. Assinatura Digital com ML-DSA (FIPS 204)

Gera um par de chaves `ML-DSA-44`, assina um payload transacional em JSON, exibe a comparação de tamanho de assinatura com relação ao ECDSA e testa a detecção de adulteração de integridade.

```bash
mvn compile exec:java -Dexec.mainClass=com.arquitetura.pqc.PostQuantumSignatureDemo
```

**Saída esperada:**
```text
=== 1. Gerando Par de Chaves ML-DSA-44 (NIST Nível 2) ===
Algoritmo da Chave Pública : ML-DSA
Tamanho da Chave Pública  : 1334 bytes
Tamanho da Chave Privada  : 54 bytes

=== 2. Assinando Dados Transacionais ===
Tamanho da Assinatura Gerada: 2420 bytes
Comparação com ECDSA (64 bytes): ~37.8x maior!

=== 3. Verificando a Assinatura Pós-Quântica ===
A assinatura é matematicamente válida? true
Adulteração de payload detectada com sucesso? true
```

---

### 2. Troca de Chaves com ML-KEM (FIPS 203)

Demonstra a negociação de segredo compartilhado entre Remetente (Cliente) e Destinatário (Servidor) utilizando `ML-KEM-768` através da API `javax.crypto.KEM`.

```bash
mvn compile exec:java -Dexec.mainClass=com.arquitetura.pqc.PostQuantumKeyExchangeDemo
```

**Saída esperada:**
```text
=== Estabelecendo Segredo Compartilhado com ML-KEM-768 ===
Tamanho do Ciphertext (enviado na rede): 1088 bytes
Algoritmo da Chave Simétrica Derivada : Generic

Chave Secreta no Cliente  : 11cc3a3a23f5790f6ebee00bd9a60b644ec50ddbabcaf78945ddc359d6c343d9
Chave Secreta no Servidor : 11cc3a3a23f5790f6ebee00bd9a60b644ec50ddbabcaf78945ddc359d6c343d9
As chaves são idênticas? true
```

---

## 🧪 Executando os Testes de Integração (Testcontainers + LocalStack)

Os testes de integração sobem um container LocalStack Pro gerenciado pelo Testcontainers e utilizam o **AWS SDK for Java v2** para interagir com o **AWS KMS** e **AWS Secrets Manager**.

Para rodar todos os testes automatizados:

```bash
mvn test
```

---

## 🛡️ Cenários de Teste Implementados

A classe `PostQuantumAwsIntegrationTest` cobre 3 cenários arquiteturais essenciais:

### 1. Envelope Encryption Híbrido (AWS KMS + ML-KEM-768)
* **Objetivo:** Garantir defesa em profundidade (*hybrid key agreement*) recomendada pelo NIST e BSI durante o período de transição pós-quântica.
* **Fluxo:**
  1. O cliente solicita uma Data Key clássica (AES-256) ao AWS KMS via `kmsClient.generateDataKey(...)`.
  2. Paralelamente, encapsula um segredo pós-quântico com `ML-KEM-768` para o destinatário.
  3. Deriva uma **chave híbrida** combinando o segredo KMS e o segredo quântico via KDF (SHA-256).
  4. Criptografa o payload com **AES-256-GCM**.
  5. O destinatário decapsula o KEM, chama `kmsClient.decrypt(...)` para obter a Data Key KMS, deriva a mesma chave híbrida e decifra o payload validando sua integridade.

### 2. Gestão de Chaves Privadas ML-DSA-44 no AWS Secrets Manager
* **Objetivo:** Armazenar chaves privadas de assinatura pós-quântica com segurança e controle de acesso na nuvem.
* **Fluxo:**
  1. A chave privada `ML-DSA-44` gerada (formato PKCS#8) é salva no AWS Secrets Manager via `secretsManagerClient.createSecret(...)`.
  2. Um serviço consumidor recupera o segredo via AWS SDK (`getSecretValue(...)`).
  3. Reconstrói a chave privada utilizando `KeyFactory.getInstance("ML-DSA")`.
  4. Assina uma transação financeira crítica e valida a assinatura com a chave pública, testando também a rejeição imediata em caso de adulteração.

### 3. Proteção de Chaves PQC com KMS Envelope Wrapping (`kms:Encrypt` / `kms:Decrypt`)
* **Objetivo:** Proteger chaves pós-quânticas de longa duração em trânsito e em repouso com envelopamento pelo KMS.
* **Fluxo:**
  1. A chave privada pós-quântica é cifrada com chave KMS mestra (`kmsClient.encrypt(...)`).
  2. O ciphertext gerado é armazenado sem expor nenhum byte em texto claro.
  3. Recuperação e decifração via `kmsClient.decrypt(...)`, reconstituindo a chave e executando com sucesso operações criptográficas.

---

## 🏛️ Considerações Arquiteturais

1. **Overhead de Rede e Armazenamento:**
   - Chaves e assinaturas pós-quânticas são consideravelmente maiores que ECDSA (P-256 gera ~64 bytes de assinatura, enquanto ML-DSA-44 gera 2420 bytes — ~38x maior).
   - O ciphertext de encapsulamento do ML-KEM-768 ocupa 1088 bytes.
2. **Defesa em Profundidade Híbrida:**
   - A combinação de algoritmos clássicos (KMS AES-256 / RSA / ECC) com reticulados (ML-KEM / ML-DSA) assegura proteção tanto contra ataques cibernéticos tradicionais quanto contra a estratégia *"Harvest Now, Decrypt Later"* (armazenar tráfego hoje para decifrar no futuro com computadores quânticos).

---

## 📄 Licença

Este projeto é disponibilizado sob a licença [MIT](LICENSE).
