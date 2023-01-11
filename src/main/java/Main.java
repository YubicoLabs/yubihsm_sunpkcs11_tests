import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import javax.crypto.*;
import javax.naming.NamingException;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.*;

public class Main {
    private static String PIN = "0001password";
    private static String SUNPKCS11_CONFIG_FILE = "src/main/resources/yubihsm_pkcs11.cfg";


    private static final String mockX509Cert = "MIIC+jCCAeKgAwIBAgIGAWbt9mc3MA0GCSqGSIb3DQEBBQUAMD4xPDA6BgNVBAMM\n" +
                                               "M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\n" +
                                               "dGlvbjAeFw0xODExMDcxMTM3MjBaFw00ODEwMzExMTM3MjBaMD4xPDA6BgNVBAMM\n" +
                                               "M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\n" +
                                               "dGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTxMBMtwHJCzNHi\n" +
                                               "d0GszdXM49jQdEZOuaLK1hyIjpuhRImJYbdvmF5cYa2suR2yw6DygWGFLafqVEuL\n" +
                                               "dXvnib3r0jBX2w7ZSrPWuJ592QUgNllHCvNG/dNgwLfCVOr9fs1ifJaa09gtQ2EG\n" +
                                               "3iV7j3AMxb7rc8x4d3nsJad+UPCyqB3HXGDRLbOT38zI72zhXm4BqiCMt6+2rcPE\n" +
                                               "+nneNiTMVjrGwzbZkCak6xnwq8/tLTtvD0+yPLQdKb4NaQfXPmYNTrzTmvYmVD8P\n" +
                                               "0bIUo/CoXIh0BkJXwHzX7J9nDW9Qd7BR2Q2vbUaou/STlWQooqoTnVnEK8zvAXkl\n" +
                                               "ubqSUPMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAGXwmRWewOcbPV/Jx6wkNDOvE\n" +
                                               "oo4bieBqeRyU/XfDYbuevfNSBnbQktThl1pR21hrJ2l9qV3D1AJDKck/x74hyjl9\n" +
                                               "mh37eqbPAdfx3yY7vN03RYWr12fW0kLJA9bsm0jYdJN4BHV/zCXlSqPS0The+Zfg\n" +
                                               "eVCiQCnEZx/z1jfxwIIg6N8Y7luPWIi36XsGqI75IhkJFw8Jup5HIB4p4P0txinm\n" +
                                               "hxzAwAjKm7yCiBA5oxX1fvSPdlwMb9mcO7qC5wKrsMyuzIpllBbGaCRFCcAtu9Zu\n" +
                                               "MvBJNrMLPK3bz4QvT5dYW/cXcjJbnIDqQKqSVV6feYk3iyS07HkaPGP3rxGpdQ==";


    public static void main(String[] args) {

        System.out.println("Java version: " + System.getProperty("java.version"));
        System.out.println("Using PKCS11 module: " + args[0]);

        String name = "YubiHSM";
        String library = args[0];
        String slotListIndex = "0";
        String pkcs11Config = "name=" + name + "\nlibrary=" + library + "\nslot=" + slotListIndex;
        pkcs11Config += "\nattributes(*,CKO_PRIVATE_KEY,CKK_RSA) = {\n" +
                        "  CKA_SIGN = true\n" +
                        "  CKA_DECRYPT = true\n" +
                        "}";
        pkcs11Config += "\nattributes(*,CKO_PRIVATE_KEY,CKK_EC) = {\n" +
                        "  CKA_SIGN = true\n" +
                        "  CKA_DERIVE = true\n" +
                        "}";

        // Java <= 8
        /*java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
        Provider provider = new sun.security.pkcs11.SunPKCS11(pkcs11ConfigStream);
        Security.addProvider(provider);*/

        // Java > 8
        try {
            FileWriter myWriter = new FileWriter(SUNPKCS11_CONFIG_FILE);
            myWriter.write(pkcs11Config);
            myWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }
        Provider provider = Security.getProvider("SunPKCS11");
        provider = provider.configure(SUNPKCS11_CONFIG_FILE);


        char[] pass = PIN.toCharArray();
        KeyStore ks = null;

        try {
            ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, pass);
        } catch (KeyStoreException e) {
            System.err.println("Failed to instantiate PKCS11 keystore");
            e.printStackTrace();
            System.exit(3);
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            System.err.println("Failed to load PKCS11 keystore");
            e.printStackTrace();
            System.exit(4);
        }


        createAndRunRsaKeyTest(ks, pass, "rsakey_2048", 2048, provider);
        createAndRunRsaKeyTest(ks, pass, "rsakey_4096", 4096, provider);
        runTest(ks,"pkcs11_test_rsa2048_cert", provider); // keys created by the setup script
        runTest(ks,"pkcs11_test_rsa3072_cert", provider); // keys created by the setup script
        runTest(ks,"pkcs11_test_rsa4096_cert", provider); // keys created by the setup script


        createAndRunEcKeyTest(ks, pass, "ec_secp224r1_key", provider);
        createAndRunEcKeyTest(ks, pass,
          "ec_secp384r1_key_b7735ac53c9bb3a9e8ec548bea91b85f06e501e2dd3af215ef3b716bbd161dc1a58650e730ad3fdee5c4493ff95005656d706b4e5e2bdf33e56d2340ce5b411f", provider);
        runTest(ks, "pkcs11_test_ecp256_cert", provider); // keys created by the setup script
        runTest(ks, "pkcs11_test_ecp384_cert", provider); // keys created by the setup script
        runTest(ks, "pkcs11_test_ecp521_cert", provider); // keys created by the setup script
        

        System.out.println("DONE!");
    }

    private static void listProviderAlgos(Provider provider) {
        System.out.println("Providers Algos: ");
        for (Provider.Service service : provider.getServices()) {
            System.out.println("*** " + service.getAlgorithm());
        }
        System.out.println();
    }

    private static void printAllAliases(KeyStore ks) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        Enumeration<String> aliases = getAllAliases(ks);
        while (aliases.hasMoreElements()) { // token has a single certificate
            String alias = aliases.nextElement();
            System.out.println("*** key alias: " + alias + " : " + ks.getKey(alias, PIN.toCharArray()).getAlgorithm() + " : " + ks.getKey(alias,
                                                                                                                                          PIN.toCharArray())
                                                                                                                                  .getFormat());
        }
        System.out.println("Printing all available keys successful.");
    }

    private static void createAndRunRsaKeyTest(KeyStore ks, char[] pass, String alias, int keySize, Provider provider) {
        KeyPairGenerator keyPairGenerator;
        KeyPair keyPair;
        X509Certificate cert;

        String importAlias = alias + "_imported";
        String genAlias = alias + "_generated";
        try {
            System.out.println("Generating " + importAlias);
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            keyPair = keyPairGenerator.generateKeyPair();
            cert = getCertificate(keyPair, true, null);
            ks.setKeyEntry(importAlias, keyPair.getPrivate(), pass, new X509Certificate[]{cert});

            System.out.println("Generating " + genAlias + " on device");
            keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
            keyPairGenerator.initialize(keySize);
            keyPair = keyPairGenerator.generateKeyPair();
            cert = getCertificate(keyPair, true, provider);
            ks.setKeyEntry(genAlias, keyPair.getPrivate(), pass, new X509Certificate[]{cert});

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Failed to generate RSA keys");
            e.printStackTrace();
            System.exit(100);
        } catch (CertificateEncodingException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.println("Failed to construct X509Certificate");
            e.printStackTrace();
            System.exit(200);
        } catch (KeyStoreException e) {
            System.err.println("Failed to import keyentry");
            e.printStackTrace();
            System.exit(300);
        }

        runTest(ks, importAlias, provider);
        runTest(ks, genAlias, provider);

        try {
            ks.deleteEntry(importAlias);
            System.out.println("----- Deleted " + importAlias);
            ks.deleteEntry(genAlias);
            System.out.println("----- Deleted " + genAlias);
        } catch (KeyStoreException e) {
            System.err.println("Failed to delete key");
            e.printStackTrace();
            System.exit(500);
        }

        if(getPrivKey(ks, importAlias) != null || getPubKey(ks, importAlias) != null) {
            System.err.println("Key still present after delete: " + importAlias);
            System.exit(600);
        }
        if(getPrivKey(ks, genAlias) != null || getPubKey(ks, genAlias) != null) {
            System.err.println("Key still present after delete: " + genAlias);
            System.exit(600);
        }
    }

    private static void createAndRunEcKeyTest(KeyStore ks, char[] pass, String alias, Provider provider) {
        KeyPairGenerator keyPairGenerator;
        KeyPair keyPair;
        X509Certificate cert;

        String curve = getCurveFromAlias(alias);
        String importAlias = alias + "_imported";
        String genAlias = alias + "_generated";
        try {

            System.out.println("Generating " + importAlias);
            keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec(curve));
            keyPair = keyPairGenerator.generateKeyPair();
            cert = getCertificate(keyPair, false,null);
            ks.setKeyEntry(importAlias, keyPair.getPrivate(), pass, new X509Certificate[]{cert});

            System.out.println("Generating " + genAlias + " on device");
            keyPairGenerator = KeyPairGenerator.getInstance("EC", provider);
            keyPairGenerator.initialize(new ECGenParameterSpec(curve));
            keyPair = keyPairGenerator.generateKeyPair();
            cert = getCertificate(keyPair, false, provider);
            ks.setKeyEntry(genAlias, keyPair.getPrivate(), pass, new X509Certificate[]{cert});

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Failed to generate RSA keys");
            e.printStackTrace();
            System.exit(100);
        } catch (CertificateEncodingException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            System.err.println("Failed to construct X509Certificate");
            e.printStackTrace();
            System.exit(200);
        } catch (KeyStoreException e) {
            System.err.println("Failed to import keyentry");
            e.printStackTrace();
            System.exit(300);
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Failed to generate EC keys");
            e.printStackTrace();
            System.exit(300);
        }

        runTest(ks, importAlias, provider);
        runTest(ks, genAlias, provider);

        try {

            ks.deleteEntry(importAlias);
            System.out.println("----- Deleted " + importAlias);
            ks.deleteEntry(genAlias);
            System.out.println("----- Deleted " + genAlias);
        } catch (KeyStoreException e) {
            System.err.println("Failed to delete key");
            e.printStackTrace();
            System.exit(500);
        }

        if(getPrivKey(ks, importAlias) != null || getPubKey(ks, importAlias) != null) {
            System.err.println("Key still present after delete: " + importAlias);
            System.exit(600);
        }
        if(getPrivKey(ks, genAlias) != null || getPubKey(ks, genAlias) != null) {
            System.err.println("Key still present after delete: " + genAlias);
            System.exit(600);
        }
    }

    private static void runTest(KeyStore ks, String alias, Provider provider) {
        System.out.println("------------- Alias: " + alias);
        PrivateKey privKey = getPrivKey(ks, alias);
        PublicKey pubKey = getPubKey(ks, alias);
        performTests(privKey, pubKey, getCurveFromAlias(alias), provider);
    }

    private static Enumeration<String> getAllAliases(KeyStore ks) {
        try {
            return ks.aliases();
        } catch (KeyStoreException e) {
            e.printStackTrace();
            System.exit(5);
        }
        return null;
    }

    private static PrivateKey getPrivKey(KeyStore ks, String alias) {
        try {
            return (PrivateKey) (ks.getKey(alias, null));
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(4);
        }
        return null;
    }

    private static PublicKey getPubKey(KeyStore ks, String alias) {
        try {
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            if(cert != null) {
                return cert.getPublicKey();
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(5);
        }
        return null;
    }

    private static void performTests(PrivateKey privKey, PublicKey pubKey, String curve, Provider provider) {
        if (privKey.getAlgorithm().equals("RSA")) {
            encryptionRSAPkcs1(pubKey, privKey, provider);
            signPkcs1(pubKey, privKey, "SHA1withRSA", provider);
            signPkcs1(pubKey, privKey, "SHA256withRSA", provider);
            signPkcs1(pubKey, privKey, "SHA384withRSA", provider);
            signPkcs1(pubKey, privKey, "SHA512withRSA", provider);
            signPss(pubKey, privKey, "SHA1withRSA/PSS", "SHA-1", provider);
            signPss(pubKey, privKey, "SHA256withRSA/PSS", "SHA-256", provider);
            signPss(pubKey, privKey, "SHA384withRSA/PSS", "SHA-384", provider);
            signPss(pubKey, privKey, "SHA512withRSA/PSS", "SHA-512", provider);
        } else if (privKey.getAlgorithm().equals("EC")) {
            signEcdsa(pubKey, privKey, "SHA1withECDSA", provider);
            signEcdsa(pubKey, privKey, "SHA256withECDSA", provider);
            signEcdsa(pubKey, privKey, "SHA384withECDSA", provider);
            signEcdsa(pubKey, privKey, "SHA512withECDSA", provider);
            if (curve != null) {
                deriveEcdh(curve, privKey, pubKey, provider);
            }
        }
    }


    private static void generateKeyPair(Provider provider) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", provider);
            keyGen.initialize(2048);
            keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(16);
        }
    }

    private static void encryptionRSAPkcs1(PublicKey pubKey, PrivateKey privKey, Provider provider) {
        String data = "TEST 1234";
        byte[] enc = null;
        byte[] dec = null;

        //Encrypt
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            enc = cipher.doFinal(data.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            System.exit(6);
        }

        // Decrypt
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", provider);
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            dec = cipher.doFinal(enc);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            System.exit(8);
        }

        Util.assertEquals("Decryption failed", new String(dec, StandardCharsets.US_ASCII), data);
        System.out.println("Encryption/Decryption test with PKCS1.5 and key " + privKey.getAlgorithm() + " successful");
    }

    private static void signPkcs1(PublicKey publicKey, PrivateKey privKey, String algo, Provider provider) {
        String data = "TEST 1234";
        byte[] signature = null;
        // Sign
        try {
            Signature sig = Signature.getInstance(algo, provider);
            sig.initSign(privKey);
            sig.update(data.getBytes());
            signature = sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.exit(10);
        }
        // Verify
        try {
            Signature sig = Signature.getInstance(algo);
            sig.initVerify(publicKey);
            sig.update(data.getBytes());
            Util.assertTrue("Signature verification with " + algo + " failed", sig.verify(signature));
            System.out.println("Signing test with " + algo + " successful");
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.exit(11);
        }
    }

    private static void signPss(PublicKey pubKey, PrivateKey privKey, String signAlgo, String hashAlgo, Provider pkcs11Prov) {
        String data = "TEST 1234";
        byte[] signature = null;

        MGF1ParameterSpec mgf1Param = new MGF1ParameterSpec(hashAlgo);
        PSSParameterSpec pssParam = new PSSParameterSpec(hashAlgo, "MGF1", mgf1Param, 32, 1);

        // Sign
        try {
            Signature sig = Signature.getInstance("RSASSA-PSS", pkcs11Prov);
            sig.setParameter(pssParam);
            sig.initSign(privKey);
            sig.update(data.getBytes());
            signature = sig.sign();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.exit(13);
        }

        // Verify
        try {
            Security.addProvider(new BouncyCastleProvider());
            Signature sig = Signature.getInstance(signAlgo, "BC");
            sig.setParameter(pssParam);
            sig.initVerify(pubKey);
            sig.update(data.getBytes());
            Util.assertTrue("Signature verification with " + signAlgo + " failed", sig.verify(signature));
            System.out.println("Signing test with " + signAlgo + " successful");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.exit(14);
        }
    }

    private static void signEcdsa(PublicKey pubKey, PrivateKey privKey, String signAlgo, Provider pkcs11Prov) {
        String data = "TEST 1234";
        byte[] signature = null;

        try {
            Signature sig = Signature.getInstance(signAlgo, pkcs11Prov);
            sig.initSign(privKey);
            sig.update(data.getBytes());
            signature = sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.exit(16);
        }

        try {
            Signature sig = Signature.getInstance(signAlgo);
            sig.initVerify(pubKey);
            sig.update(data.getBytes());
            Util.assertTrue("Signature verification with " + signAlgo + " failed", sig.verify(signature));
            System.out.println("Signing test with " + signAlgo + " successful");
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.exit(17);
        }
    }

    private static void deriveEcdh(String curve, PrivateKey hsmPrivKey, PublicKey hsmPubKey, Provider provider) {
        KeyPair ecExtKeypair = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            ecExtKeypair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            System.exit(19);
        }

        byte[] extEcdh = null;
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(ecExtKeypair.getPrivate());
            keyAgreement.doPhase(hsmPubKey, true);
            extEcdh = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            System.exit(20);
        }

        byte[] hsmEcdh = null;
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", provider);
            keyAgreement.init(hsmPrivKey);
            keyAgreement.doPhase(ecExtKeypair.getPublic(), true);
            hsmEcdh = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            System.exit(20);
        }

        Util.assertByteArrayEquals("Deriving ECDH with curve " + curve + " failed", hsmEcdh, extEcdh);
        System.out.println("Deriving ECDH with curve " + curve + " successful");
    }

    private static String getCurveFromAlias(String alias) {
        if (alias.contains("ecp224") || alias.contains("secp224")) {
            return "secp224r1";
        }
        if (alias.contains("ecp256") || alias.contains("secp256")) {
            return "secp256r1";
        }
        if (alias.contains("ecp384") || alias.contains("secp384")) {
            return "secp384r1";
        }
        if (alias.contains("ecp521") || alias.contains("secp521")) {
            return "secp521r1";
        }
        return null;
    }


    private static X509Certificate getCertificate(KeyPair keypair, boolean isRsa, Provider provider)
            throws NoSuchAlgorithmException, CertificateEncodingException, NoSuchProviderException, InvalidKeyException, SignatureException {
        final UUID uuid = new UUID(3, 3);
        final X509V3CertificateGenerator generator = new X509V3CertificateGenerator();

        final Calendar calendar = Calendar.getInstance();

        final Vector<ASN1ObjectIdentifier> attrsVector = new Vector<ASN1ObjectIdentifier>();
        final Hashtable<ASN1ObjectIdentifier, String> attrsHash = new Hashtable<ASN1ObjectIdentifier, String>();

        attrsHash.put(X509Principal.CN, "rsakeyCert");
        attrsVector.add(X509Principal.CN);

        generator.setSubjectDN(new X509Principal(attrsVector, attrsHash));

        calendar.add(Calendar.HOUR, -1);
        generator.setNotBefore(calendar.getTime());

        calendar.add(Calendar.HOUR, 100);
        generator.setNotAfter(calendar.getTime());

        // Reuse the UUID time as a SN
        generator.setSerialNumber(BigInteger.valueOf(123456789L).abs());

        //generator.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
        //                       new AuthorityKeyIdentifierStructure(caCert));

        //generator.addExtension(X509Extensions.SubjectKeyIdentifier, false,
        //                       new SubjectKeyIdentifierStructure(sshKey.getKey()));

        StringBuilder hostnameAndUUIDBuilder = new StringBuilder("local");
        hostnameAndUUIDBuilder.append(':');
        hostnameAndUUIDBuilder.append(uuid.toString());
        generator.addExtension(X509Extensions.IssuingDistributionPoint, false,
                               hostnameAndUUIDBuilder.toString().getBytes());

        // Not a CA
        generator.addExtension(X509Extensions.BasicConstraints, true,
                               new BasicConstraints(false));

        generator.setIssuerDN(new X509Principal(attrsVector, attrsHash));
        generator.setPublicKey(keypair.getPublic());
        if(isRsa) {
            generator.setSignatureAlgorithm("SHA1withRSA");
        } else {
            generator.setSignatureAlgorithm("SHA256withECDSA");
        }

        if(provider == null) {
            return generator.generate(keypair.getPrivate());
        } else {
            Security.addProvider(provider);
            return generator.generate(keypair.getPrivate(), provider.getName());
        }
    }

    private static X509Certificate parseCertificate() throws CertificateException {
        byte [] decoded = Base64.getDecoder().decode(mockX509Cert);
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(decoded));
    }

    private static X509Certificate convertStringToX509Cert() throws CertificateException, IOException {
        InputStream targetStream = new ByteArrayInputStream(mockX509Cert.getBytes());
        System.out.println("-------- targetStream == NULL? " + (targetStream == null) + "   .   available: " + targetStream.available());
        return (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(targetStream);
    }

    private static X509Certificate convertToX509Certificate() throws CertificateException {
        CertificateFactory fac=CertificateFactory.getInstance("X509");
        ByteArrayInputStream in=new ByteArrayInputStream(mockX509Cert.getBytes());
        X509Certificate cert=(X509Certificate)fac.generateCertificate(in);
        return cert;
    }
}