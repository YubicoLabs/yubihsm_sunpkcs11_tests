import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Enumeration;

public class Main {
    private static String PIN = "0001password";
    private static String SUNPKCS11_CONFIG_FILE = "src/main/resources/yubihsm_pkcs11.cfg";

    public static void main(String[] args) {

        System.out.println("Using PKCS11 module: " + args[0]);

        String name = "YubiHSM";
        String library = args[0];
        String slotListIndex = "0";
        String pkcs11Config = "name=" + name + "\nlibrary=" + library + "\nslot=" + slotListIndex;

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

        listProviderAlgos(provider);

        Enumeration<String> aliases = getAllAliases(ks);
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("----- " + alias + ":");
            PrivateKey privKey = getPrivKey(ks, alias);
            PublicKey pubKey = getPubKey(ks, alias);
            performTests(privKey, pubKey, getCurveFromAlias(alias), provider);
        }

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
                                                                                                                                          PIN.toCharArray()).getFormat());
        }
        System.out.println("Printing all available keys successful.");
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
            return  (PrivateKey) (ks.getKey(alias, null));
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(4);
        }
        return null;
    }

    private static PublicKey getPubKey(KeyStore ks, String alias) {
        try {
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            return cert.getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(5);
        }
        return null;
    }

    private static void performTests(PrivateKey privKey, PublicKey pubKey, String curve, Provider provider) {
        if(privKey.getAlgorithm().equals("RSA")) {
            encryptionRSAPkcs1(pubKey, privKey, provider);
            signPkcs1(pubKey, privKey, "SHA1withRSA", provider);
            signPkcs1(pubKey, privKey, "SHA256withRSA", provider);
            signPkcs1(pubKey, privKey, "SHA384withRSA", provider);
            signPkcs1(pubKey, privKey, "SHA512withRSA", provider);
            signPss(pubKey, privKey, "SHA1withRSA/PSS", "SHA-1", provider);
            signPss(pubKey, privKey, "SHA256withRSA/PSS", "SHA-256", provider);
            signPss(pubKey, privKey, "SHA384withRSA/PSS","SHA-384", provider);
            signPss(pubKey, privKey, "SHA512withRSA/PSS", "SHA-512", provider);
        } else if(privKey.getAlgorithm().equals("EC")) {
            signEcdsa(pubKey, privKey, "SHA1withECDSA", provider);
            signEcdsa(pubKey, privKey, "SHA256withECDSA", provider);
            signEcdsa(pubKey, privKey, "SHA384withECDSA", provider);
            signEcdsa(pubKey, privKey, "SHA512withECDSA", provider);
            if(curve != null) {
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
        if(alias.contains("ecp256")) {
            return "secp256r1";
        }
        if(alias.contains("ecp384")) {
            return "secp384r1";
        }
        if(alias.contains("ecp521")) {
            return "secp521r1";
        }
        return null;
    }
}