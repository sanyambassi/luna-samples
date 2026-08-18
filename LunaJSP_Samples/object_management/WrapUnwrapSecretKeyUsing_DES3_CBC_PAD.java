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
	- This sample demonstrates how wrap and then unwrap a secret key using CKM_DES3_CBC_PAD mechanism.
	- This sample generates a DES-3 key and an AES-128 key.
		o AES-128 key is the key to be wrapped and unwrapped.
		o DES-3 key is the wrapping key.
	- All keys are generated and unwrapped as a session key by this sample.
	- This sample may fail when used on a slot configured to operate in FIPS mode.
*/



import java.security.Security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class WrapUnwrapSecretKeyUsing_DES3_CBC_PAD {

	private static String slotPassword = null;
	private static String slotLabel = null;
	private static LunaSlotManager slotManager = null;
	private static SecretKey wrappingKey = null; // for storing wrapping key.
	private static SecretKey toBeWrapped = null; // for storing the key to be wrapped.
	private static SecretKey unwrappedKey = null;// for storing unwrapped key.
	private static byte[] wrappedKey = null; // for storing encrypted key bytes.
	private static final int KEY_SIZE = 128;
	private static final IvParameterSpec IVSPEC = new IvParameterSpec("12345678".getBytes());
	private static final String PROVIDER = "LunaProvider";


	// Prints the proper syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ WrapUnwrapSecretKeyUsing_DES3_CBC_PAD ]\n");
		System.out.println("Usage-");
		System.out.println("java WrapUnwrapSecretKeyUsing_DES3_CBC_PAD <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java WrapUnwrapSecretKeyUsing_DES3_CBC_PAD myPartition userpin\n");
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


        // generates aes-128 key.
        private static void generateAESKey() throws Exception {
		slotManager.setSecretKeysExtractable(true); // Sets CKA_EXTRACTABLE as TRUE, else C_Wrap would fail.
                KeyGenerator keyGen = KeyGenerator.getInstance("AES", PROVIDER);
                keyGen.init(KEY_SIZE);
                toBeWrapped = keyGen.generateKey();
                if(wrappingKey!=null) {
                        System.out.println("AES wrapping key generated.");
                }
        }


        // generates des-3 key.
        private static void generateDES3Key() throws Exception {
                KeyGenerator keyGen = KeyGenerator.getInstance("DES3", PROVIDER);
                wrappingKey = keyGen.generateKey();
                if(toBeWrapped!=null) {
                        System.out.println("DES-3 key generated.");
                }
        }


	// wraps aes-key using des3 key.
	private static void wrapKey() throws Exception {
		Cipher wrap = Cipher.getInstance("DESede/CBC/PKCS5Padding", PROVIDER);
		wrap.init(Cipher.WRAP_MODE, wrappingKey, IVSPEC);
		wrappedKey = wrap.wrap(toBeWrapped);
		System.out.println("AES key wrapped.");
	}


	// unwraps the wrapped aes-key
	private static void unwrapKey() throws Exception {
		Cipher unwrap = Cipher.getInstance("DESede/CBC/PKCS5Padding", PROVIDER);
		unwrap.init(Cipher.UNWRAP_MODE, wrappingKey, IVSPEC);
		unwrappedKey = (SecretKey)unwrap.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
		System.out.println("Wrapped key unwrapped as a " + unwrappedKey.getAlgorithm() + " key.");
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
			generateDES3Key();
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
