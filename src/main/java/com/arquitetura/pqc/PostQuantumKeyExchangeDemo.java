package com.arquitetura.pqc;

import javax.crypto.KEM;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.HexFormat;

/**
 * Exemplo de encapsulamento e decapsulamento de segredo compartilhado
 * via ML-KEM (FIPS 203) nativo no Java 25/27.
 */
public class PostQuantumKeyExchangeDemo {

    public static void main(String[] args) throws Exception {
        System.out.println("=== Estabelecendo Segredo Compartilhado com ML-KEM-768 ===");

        // 1. O Destinatário (Servidor) gera seu par de chaves ML-KEM
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair servidorKeyPair = kpg.generateKeyPair();

        // 2. O Remetente (Cliente) quer negociar uma chave simétrica segura (ex: AES-256)
        KEM kemCliente = KEM.getInstance("ML-KEM-768");
        KEM.Encapsulator encapsulador = kemCliente.newEncapsulator(servidorKeyPair.getPublic());
        
        // Gera o pacote encapsulado (enviado pela rede) e a chave secreta compartilhada
        KEM.Encapsulated resultadoEncapsulamento = encapsulador.encapsulate();
        byte[] ciphertext = resultadoEncapsulamento.encapsulation();
        SecretKey chaveSimetricaCliente = resultadoEncapsulamento.key();

        System.out.println("Tamanho do Ciphertext (enviado na rede): " + ciphertext.length + " bytes");
        System.out.println("Algoritmo da Chave Simétrica Derivada : " + chaveSimetricaCliente.getAlgorithm());

        // 3. O Servidor recebe o ciphertext e decapsula usando sua chave privada
        KEM kemServidor = KEM.getInstance("ML-KEM-768");
        KEM.Decapsulator decapsulador = kemServidor.newDecapsulator(servidorKeyPair.getPrivate());
        SecretKey chaveSimetricaServidor = decapsulador.decapsulate(ciphertext);

        // 4. Validação: ambos os lados possuem exatamente a mesma chave simétrica
        String hexCliente = HexFormat.of().formatHex(chaveSimetricaCliente.getEncoded());
        String hexServidor = HexFormat.of().formatHex(chaveSimetricaServidor.getEncoded());

        System.out.println("\nChave Secreta no Cliente  : " + hexCliente);
        System.out.println("Chave Secreta no Servidor : " + hexServidor);
        System.out.println("As chaves são idênticas? " + hexCliente.equals(hexServidor));
    }
}
