package com.arquitetura.pqc;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.nio.charset.StandardCharsets;

/**
 * Demonstração de assinatura e verificação digital pós-quântica
 * utilizando ML-DSA (FIPS 204) nativo do Java 25/27.
 */
public class PostQuantumSignatureDemo {

    public static void main(String[] args) throws Exception {
        System.out.println("=== 1. Gerando Par de Chaves ML-DSA-44 (NIST Nível 2) ===");
        
        // Você pode instanciar "ML-DSA" (padrão) ou especificar o conjunto de parâmetros:
        // "ML-DSA-44", "ML-DSA-65" ou "ML-DSA-87"
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA-44");
        KeyPair keyPair = keyGen.generateKeyPair();
        
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("Algoritmo da Chave Pública : " + publicKey.getAlgorithm());
        System.out.println("Tamanho da Chave Pública  : " + publicKey.getEncoded().length + " bytes");
        System.out.println("Tamanho da Chave Privada  : " + privateKey.getEncoded().length + " bytes");

        System.out.println("\n=== 2. Assinando Dados Transacionais ===");
        String payloadTransacao = """
            {
                "origem": "carteira-institucional-001",
                "destino": "tesouro-seguro-pqc",
                "valor": 1500000.00,
                "moeda": "BRL",
                "timestamp": "2026-10-09T14:30:00Z"
            }
            """;

        byte[] dados = payloadTransacao.getBytes(StandardCharsets.UTF_8);

        // Instancia a assinatura ML-DSA nativa do SunJCE
        Signature signer = Signature.getInstance("ML-DSA");
        signer.initSign(privateKey);
        signer.update(dados);
        byte[] assinatura = signer.sign();

        System.out.println("Tamanho da Assinatura Gerada: " + assinatura.length + " bytes");
        System.out.printf("Comparação com ECDSA (64 bytes): ~%.1fx maior!\n", (assinatura.length / 64.0));

        System.out.println("\n=== 3. Verificando a Assinatura Pós-Quântica ===");
        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(publicKey);
        verifier.update(dados);
        boolean assinaturaValida = verifier.verify(assinatura);

        System.out.println("A assinatura é matematicamente válida? " + assinaturaValida);

        // Teste de integridade (alterando 1 byte do payload)
        byte[] dadosAdulterados = payloadTransacao.replace("1500000", "9999999").getBytes(StandardCharsets.UTF_8);
        verifier.initVerify(publicKey);
        verifier.update(dadosAdulterados);
        boolean adulteracaoDetectada = !verifier.verify(assinatura);

        System.out.println("Adulteração de payload detectada com sucesso? " + adulteracaoDetectada);
    }
}
