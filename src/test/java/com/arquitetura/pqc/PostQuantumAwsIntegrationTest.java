package com.arquitetura.pqc;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import javax.crypto.Cipher;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Testes de integração utilizando JUnit 5, Testcontainers (LocalStack Pro) e AWS SDK v2,
 * validando cenários arquiteturais com criptografia pós-quântica (PQC - FIPS 203 ML-KEM e FIPS 204 ML-DSA).
 */
@Testcontainers
class PostQuantumAwsIntegrationTest {

    @Container
    static LocalStackContainer localStack;

    static {
        String authToken = loadLocalStackAuthToken();
        DockerImageName imageName;
        if (!authToken.isEmpty()) {
            imageName = DockerImageName.parse("localstack/localstack-pro:latest")
                    .asCompatibleSubstituteFor("localstack/localstack");
        } else {
            imageName = DockerImageName.parse("localstack/localstack:latest");
        }
        localStack = new LocalStackContainer(imageName)
                .withServices(
                        LocalStackContainer.Service.KMS,
                        LocalStackContainer.Service.SECRETSMANAGER
                );
        if (!authToken.isEmpty()) {
            localStack.withEnv("LOCALSTACK_AUTH_TOKEN", authToken);
        }
    }

    private static KmsClient kmsClient;
    private static SecretsManagerClient secretsManagerClient;

    private static String loadLocalStackAuthToken() {
        // 1. Tenta carregar de config.properties
        Path configPath = Path.of("config.properties");
        if (Files.exists(configPath)) {
            try (InputStream is = Files.newInputStream(configPath)) {
                Properties props = new Properties();
                props.load(is);
                String token = props.getProperty("localstack.auth.token");
                if (token != null && !token.isBlank() && !token.contains("SUA_CHAVE")) {
                    return token.trim();
                }
            } catch (Exception ignored) {
            }
        }
        // 2. Fallback: variavel de ambiente LOCALSTACK_AUTH_TOKEN
        String envToken = System.getenv("LOCALSTACK_AUTH_TOKEN");
        if (envToken != null && !envToken.isBlank()) {
            return envToken.trim();
        }
        return "";
    }

    @BeforeAll
    static void setUp() {
        kmsClient = KmsClient.builder()
                .endpointOverride(localStack.getEndpoint())
                .region(Region.of(localStack.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(localStack.getAccessKey(), localStack.getSecretKey())
                ))
                .build();

        secretsManagerClient = SecretsManagerClient.builder()
                .endpointOverride(localStack.getEndpoint())
                .region(Region.of(localStack.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(localStack.getAccessKey(), localStack.getSecretKey())
                ))
                .build();
    }

    @AfterAll
    static void tearDown() {
        if (kmsClient != null) {
            kmsClient.close();
        }
        if (secretsManagerClient != null) {
            secretsManagerClient.close();
        }
    }

    @Test
    @DisplayName("Cenário 1: Envelope Encryption Híbrido Pós-Quântico (AWS KMS Data Key + ML-KEM-768)")
    void testHybridPostQuantumEnvelopeEncryptionWithKmsAndMlKem() throws Exception {
        // 1. Cria uma chave mestra simétrica no AWS KMS via AWS SDK
        CreateKeyResponse createKeyResponse = kmsClient.createKey(CreateKeyRequest.builder()
                .description("Chave KMS para Envelope Hibrido PQC")
                .keyUsage(KeyUsageType.ENCRYPT_DECRYPT)
                .build());
        String kmsKeyId = createKeyResponse.keyMetadata().keyId();
        assertNotNull(kmsKeyId);

        // 2. Destinatário gera par de chaves pós-quânticas ML-KEM-768 (FIPS 203)
        KeyPairGenerator kemKpg = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair destinatarioKeyPair = kemKpg.generateKeyPair();

        // 3. Remetente solicita chave de dados (Data Key AES-256) ao AWS KMS
        GenerateDataKeyResponse dataKeyResponse = kmsClient.generateDataKey(GenerateDataKeyRequest.builder()
                .keyId(kmsKeyId)
                .keySpec(DataKeySpec.AES_256)
                .build());
        byte[] kmsPlaintextDataKey = dataKeyResponse.plaintext().asByteArray();
        SdkBytes kmsEncryptedDataKey = dataKeyResponse.ciphertextBlob();

        // 4. Remetente realiza encapsulamento KEM pós-quântico com a chave pública do destinatário
        KEM kem = KEM.getInstance("ML-KEM-768");
        KEM.Encapsulator encapsulator = kem.newEncapsulator(destinatarioKeyPair.getPublic());
        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        byte[] kemCiphertext = encapsulated.encapsulation();
        SecretKey kemSharedSecret = encapsulated.key();

        // 5. Remetente deriva Chave Híbrida Pós-Quântica (KDF combinando KMS Data Key + ML-KEM Secret)
        byte[] chaveHibridaRemetente = derivarChaveHibrida(kmsPlaintextDataKey, kemSharedSecret.getEncoded());

        // 6. Criptografa o payload sensível com AES-256-GCM usando a chave híbrida
        String payloadTransacao = """
                {"transacaoId":"tx-98765","valor":2500000.00,"moeda":"BRL","status":"APROVADO"}
                """;
        byte[] dadosOriginais = payloadTransacao.getBytes(StandardCharsets.UTF_8);

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipherEnc = Cipher.getInstance("AES/GCM/NoPadding");
        cipherEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chaveHibridaRemetente, "AES"), new GCMParameterSpec(128, iv));
        byte[] ciphertextPayload = cipherEnc.doFinal(dadosOriginais);

        // ======================= RECEPTOR / DESTINATÁRIO =======================
        // 7. Destinatário decapsula o ciphertext ML-KEM usando sua chave privada
        KEM.Decapsulator decapsulator = kem.newDecapsulator(destinatarioKeyPair.getPrivate());
        SecretKey kemSharedSecretDestinatario = decapsulator.decapsulate(kemCiphertext);

        // 8. Destinatário decifra a KMS Data Key chamando o AWS KMS via AWS SDK
        DecryptResponse decryptResponse = kmsClient.decrypt(DecryptRequest.builder()
                .ciphertextBlob(kmsEncryptedDataKey)
                .keyId(kmsKeyId)
                .build());
        byte[] kmsDecryptedDataKey = decryptResponse.plaintext().asByteArray();

        // 9. Destinatário deriva a mesma Chave Híbrida
        byte[] chaveHibridaDestinatario = derivarChaveHibrida(kmsDecryptedDataKey, kemSharedSecretDestinatario.getEncoded());
        assertArrayEquals(chaveHibridaRemetente, chaveHibridaDestinatario, "As chaves híbridas devem ser estritamente idênticas");

        // 10. Destinatário descriptografa o payload e valida os dados
        Cipher cipherDec = Cipher.getInstance("AES/GCM/NoPadding");
        cipherDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveHibridaDestinatario, "AES"), new GCMParameterSpec(128, iv));
        byte[] dadosDescriptografados = cipherDec.doFinal(ciphertextPayload);

        assertEquals(payloadTransacao, new String(dadosDescriptografados, StandardCharsets.UTF_8));

        // Teste de adulteração: adulterar 1 byte no ciphertext deve falhar na autenticação GCM
        byte[] ciphertextAdulterado = ciphertextPayload.clone();
        ciphertextAdulterado[0] ^= 0x5A;
        Cipher cipherTamper = Cipher.getInstance("AES/GCM/NoPadding");
        cipherTamper.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chaveHibridaDestinatario, "AES"), new GCMParameterSpec(128, iv));
        assertThrows(Exception.class, () -> cipherTamper.doFinal(ciphertextAdulterado),
                "Qualquer modificação no payload cifrado deve causar falha de integridade");
    }

    @Test
    @DisplayName("Cenário 2: Gestão Segura de Chave Privada ML-DSA-44 no AWS Secrets Manager")
    void testPostQuantumSignatureMlDsaWithAwsSecretsManager() throws Exception {
        // 1. Gera par de chaves ML-DSA-44 nativas do Java 27 (FIPS 204)
        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("ML-DSA-44");
        KeyPair keyPairOriginal = dsaKpg.generateKeyPair();
        PrivateKey privateKeyOriginal = keyPairOriginal.getPrivate();
        PublicKey publicKeyOriginal = keyPairOriginal.getPublic();

        // 2. Armazena a chave privada com segurança no AWS Secrets Manager via AWS SDK
        String secretName = "pqc/chaves/assinador-mldsa-44";
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKeyOriginal.getEncoded());

        secretsManagerClient.createSecret(CreateSecretRequest.builder()
                .name(secretName)
                .description("Chave privada ML-DSA-44 para assinatura digital pós-quântica")
                .secretString(privateKeyBase64)
                .build());

        // 3. Serviço consumidor recupera a chave privada via AWS SDK
        GetSecretValueResponse secretValueResponse = secretsManagerClient.getSecretValue(
                GetSecretValueRequest.builder().secretId(secretName).build()
        );
        String secretStringRecuperada = secretValueResponse.secretString();
        assertNotNull(secretStringRecuperada);

        // 4. Reconstrói a chave privada ML-DSA a partir dos bytes PKCS#8 recuperados
        byte[] privateKeyBytes = Base64.getDecoder().decode(secretStringRecuperada);
        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA");
        PrivateKey privateKeyRecuperada = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        assertEquals("ML-DSA", privateKeyRecuperada.getAlgorithm());

        // 5. Assina um payload transacional com a chave privada recuperada do AWS Secrets Manager
        byte[] payload = "TRANSFERENCIA_PIX_PQC:ORIGEM=CONTA_A:DESTINO=CONTA_B:VALOR=50000.00"
                .getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance("ML-DSA");
        signer.initSign(privateKeyRecuperada);
        signer.update(payload);
        byte[] assinatura = signer.sign();

        assertTrue(assinatura.length > 0, "A assinatura ML-DSA gerada deve ter bytes válidos");

        // 6. Verifica a assinatura com a chave pública
        Signature verifier = Signature.getInstance("ML-DSA");
        verifier.initVerify(publicKeyOriginal);
        verifier.update(payload);
        boolean assinaturaValida = verifier.verify(assinatura);
        assertTrue(assinaturaValida, "A assinatura ML-DSA deve ser matematicamente válida");

        // 7. Verifica detecção de adulteração de payload
        byte[] payloadAdulterado = "TRANSFERENCIA_PIX_PQC:ORIGEM=CONTA_A:DESTINO=CONTA_B:VALOR=99999.00"
                .getBytes(StandardCharsets.UTF_8);
        verifier.initVerify(publicKeyOriginal);
        verifier.update(payloadAdulterado);
        assertFalse(verifier.verify(assinatura), "Assinatura deve ser rejeitada após adulteração do payload");
    }

    @Test
    @DisplayName("Cenário 3: Criptografia da Chave Privada PQC via AWS KMS Envelope (kms:Encrypt / kms:Decrypt)")
    void testPostQuantumPrivateKeyProtectionViaKmsEnvelope() throws Exception {
        // 1. Cria chave KMS no LocalStack via AWS SDK
        CreateKeyResponse createKey = kmsClient.createKey(CreateKeyRequest.builder()
                .description("Chave Mestra KMS para Criptografia de Chaves PQC")
                .build());
        String kmsKeyId = createKey.keyMetadata().keyId();

        // 2. Gera par de chaves ML-KEM-768
        KeyPairGenerator kemKpg = KeyPairGenerator.getInstance("ML-KEM-768");
        KeyPair kemKeyPair = kemKpg.generateKeyPair();
        byte[] privateKeyBytes = kemKeyPair.getPrivate().getEncoded();

        // 3. Criptografa a chave privada pós-quântica diretamente no AWS KMS
        EncryptResponse encryptResponse = kmsClient.encrypt(EncryptRequest.builder()
                .keyId(kmsKeyId)
                .plaintext(SdkBytes.fromByteArray(privateKeyBytes))
                .build());
        SdkBytes encryptedPrivateKey = encryptResponse.ciphertextBlob();
        assertNotNull(encryptedPrivateKey);
        assertFalse(HexFormat.of().formatHex(encryptedPrivateKey.asByteArray())
                .contains(HexFormat.of().formatHex(privateKeyBytes)), "Bytes originais não devem estar em texto claro");

        // 4. Descriptografa a chave privada via AWS KMS
        DecryptResponse decryptResponse = kmsClient.decrypt(DecryptRequest.builder()
                .keyId(kmsKeyId)
                .ciphertextBlob(encryptedPrivateKey)
                .build());
        byte[] decryptedBytes = decryptResponse.plaintext().asByteArray();

        assertArrayEquals(privateKeyBytes, decryptedBytes, "Os bytes da chave privada decifrada devem ser idênticos");

        // 5. Reconstrói a chave privada e executa decapsulamento com sucesso
        KeyFactory keyFactory = KeyFactory.getInstance("ML-KEM");
        PrivateKey restoredPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedBytes));

        KEM kem = KEM.getInstance("ML-KEM-768");
        KEM.Encapsulated enc = kem.newEncapsulator(kemKeyPair.getPublic()).encapsulate();
        SecretKey decapsulatedSecret = kem.newDecapsulator(restoredPrivateKey).decapsulate(enc.encapsulation());

        assertArrayEquals(enc.key().getEncoded(), decapsulatedSecret.getEncoded(),
                "O segredo compartilhado derivado com a chave recuperada pelo KMS deve ser idêntico");
    }

    /**
     * Função KDF híbrida pós-quântica (SHA-256 combinando a chave clássica do AWS KMS e o segredo quântico ML-KEM).
     */
    private static byte[] derivarChaveHibrida(byte[] kmsDataKey, byte[] kemSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(kmsDataKey);
        digest.update("PQC-KMS-HYBRID-KDF".getBytes(StandardCharsets.UTF_8));
        return digest.digest(kemSecret);
    }
}
