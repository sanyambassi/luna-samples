        /*********************************************************************************\
        *                                                                                *
        * This file is part of the "luna-samples" project.                               *
        *                                                                                *
        * The "luna-samples" project is provided under the MIT license (see the          *
        * following Web site for further details: https://mit-license.org/ ).            *
        *                                                                                *
        * Copyright © 2024 Thales Group                                                  *
        *                                                                                *
        **********************************************************************************

        OBJECTIVE :
	- This sample demonstrates how wrap and unwrap a private key using CKM_AES_KWP mechanism.
	- It generates an AES-256 key for wrapping/unwrapping an RSA Private Key.
	- All keys are generated and unwrapped as a session key by this sample.
	- This sample requires a Luna HSM, configured as KeyExport.
*/



import java.security.Security;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class WrapUnwrapPrivateKeyUsing_AES_KWP {

	private static String slotPassword = null;
	private static String slotLabel = null;
	private static LunaSlotManager slotManager = null;
	private static SecretKey wrappingKey = null; // for storing wrapping key.
	private static PrivateKey rsaPrivateKey = null;
	private static PrivateKey unwrappedPrivateKey = null;// for storing unwrapped key.
	private static byte[] wrappedPrivateKey = null; // for storing encrypted key bytes.
	private static final int AES_KEY_SIZE = 128;
	private static final int RSA_KEY_SIZE = 2048;
	private static final IvParameterSpec IVSPEC = new IvParameterSpec("1234".getBytes());
	private static final String PROVIDER = "LunaProvider";


	// Prints the proper syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ WrapUnwrapPrivateKeyUsing_AES_KWP ]\n");
		System.out.println("Usage-");
		System.out.println("java WrapUnwrapPrivateKeyUsing_AES_KWP <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java WrapUnwrapPrivateKeyUsing_AES_KWP myPartition userpin\n");
	}


        // Add LunaProvider to security provider list.
        private static void addLunaProvider() {
                if(Security.getProvider(PROVIDER)==null) {
                        Security.insertProviderAt(new com.safenetinc.luna.provider.LunaProvider(), 3);
                        System.out.println("LunaProvider added to java.security");
                } else {
                        System.out.println("LunaProvider found in java.security");
                }
        }


        // generates AES-256 key.
        private static void generateAESKey() throws Exception {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES", PROVIDER);
                keyGen.init(AES_KEY_SIZE);
                wrappingKey = keyGen.generateKey();
		System.out.println("AES key generated for wrapping.");
        }


	// generates RSA-2048 keypair.
	private static void generateRSAPrivateKey() throws Exception {
		slotManager.setPrivateKeysExtractable(true); // sets private key as extractable, i.e. CKA_EXTRACTABLE=TRUE
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", PROVIDER);
		keyPairGen.initialize(RSA_KEY_SIZE);
		rsaPrivateKey = keyPairGen.generateKeyPair().getPrivate();
		System.out.println("RSA keypair generated.");
	}


	// wraps private key.
	private static void wrapKey() throws Exception {
		Cipher wrap = Cipher.getInstance("AES/KWP/NoPadding", PROVIDER);
		wrap.init(Cipher.WRAP_MODE, wrappingKey, IVSPEC);
		wrappedPrivateKey = wrap.wrap(rsaPrivateKey);
		System.out.println("RSA private key wrapped.");
	}


	// unwraps a wrapped private key
	private static void unwrapKey() throws Exception {
		Cipher unwrap = Cipher.getInstance("AES/KWP/NoPadding", PROVIDER);
		unwrap.init(Cipher.UNWRAP_MODE, wrappingKey, IVSPEC);
		unwrappedPrivateKey = (PrivateKey)unwrap.unwrap(wrappedPrivateKey, "RSA", Cipher.PRIVATE_KEY);
		System.out.println("Wrapped private key unwrapped.");
	}


	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();
			addLunaProvider();
			slotManager.login(slotLabel, slotPassword); // Performs C_Login
			System.out.println("LOGIN: SUCCESS");
			generateAESKey();
			generateRSAPrivateKey();
			wrapKey();
			unwrapKey();
			slotManager.logout(); // Performs C_Logout
			System.out.println("LOGOUT: SUCCESS");
		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(LunaException le) {
			System.out.println("ERROR: "+ le.getMessage());
		} catch(Exception exception) {
			System.out.println("ERROR: "+ exception.getMessage());
		}
	}
}
