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
	- This sample demonstrates how wrap and then unwrap a secret key using CKM_AES_CBC_PAD mechanism.
	- It generates two AES-256 key. One for wrapping and the other to be wrapped.
	- All keys are generated and unwrapped as a session key by this sample.
	- This sample may fail when executed on a slot configured to operate in FIPS mode.
*/



import java.security.Security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class WrapUnwrapSecretKeyUsing_AES_CBC_PAD {

	private static String slotPassword = null;
	private static String slotLabel = null;
	private static LunaSlotManager slotManager = null;
	private static SecretKey wrappingKey = null; // for storing wrapping key.
	private static SecretKey toBeWrapped = null; // for storing the key to be wrapped.
	private static SecretKey unwrappedKey = null;// for storing unwrapped key.
	private static byte[] wrappedKey = null; // for storing encrypted key bytes.
	private static final int KEY_SIZE = 128;
	private static final IvParameterSpec IVSPEC = new IvParameterSpec("1234567812345678".getBytes());
	private static final String PROVIDER = "LunaProvider";


	// Prints the proper syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ WrapUnwrapSecretKeyUsing_AES_CBC_PAD ]\n");
		System.out.println("Usage-");
		System.out.println("java WrapUnwrapSecretKeyUsing_AES_CBC_PAD <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java WrapUnwrapSecretKeyUsing_AES_CBC_PAD myPartition userpin\n");
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
        private static SecretKey generateAESKey() throws Exception {
		SecretKey key;
		slotManager.setSecretKeysExtractable(true); // Sets CKA_EXTRACTABLE as TRUE, else C_Wrap would fail.
                KeyGenerator keyGen = KeyGenerator.getInstance("AES", PROVIDER);
                keyGen.init(KEY_SIZE);
                key = keyGen.generateKey();
                if(key==null) {
                        System.exit(1);
                }
		return key;
        }


	// wraps aes-key using des3 key.
	private static void wrapKey() throws Exception {
		Cipher wrap = Cipher.getInstance("AES/CBC/PKCS5Padding", PROVIDER);
		wrap.init(Cipher.WRAP_MODE, wrappingKey, IVSPEC);
		wrappedKey = wrap.wrap(toBeWrapped);
		System.out.println("AES key wrapped.");
	}


	// unwraps the wrapped aes-key
	private static void unwrapKey() throws Exception {
		Cipher unwrap = Cipher.getInstance("AES/CBC/PKCS5Padding", PROVIDER);
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
			wrappingKey = generateAESKey();
			System.out.println("AES wrapping key generated.");
			toBeWrapped = generateAESKey();
			System.out.println("AES key to be wrapped, generated.");
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
