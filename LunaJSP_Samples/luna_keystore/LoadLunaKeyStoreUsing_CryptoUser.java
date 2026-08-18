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
	- This sample demonstrates how to load Luna Keystore using Crypto User Role.
	- Crypto User is a vendor-defined role for Luna HSMs that provides read-only access to a partition.
	- This sample uses slotlabel to login.
	- There is no logout function in Java KeyStore so LunaProvider is programmed to logout before an application close(finalize).
*/


import java.security.Security;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class LoadLunaKeyStoreUsing_CryptoUser {

	private static String cryptoUserPassword = null;
	private static String slotLabel = null;
	private static final String PROVIDER = "LunaProvider";

	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ LoadLunaKeyStoreUsing_CryptoUser ]\n");
		System.out.println("Usage-");
		System.out.println("java LoadLunaKeyStoreUsing_CryptoUser <slot_label> <crypto_user_password>\n");
		System.out.println("Example -");
		System.out.println("java LoadLunaKeyStoreUsing_CryptoUser myPartition cryptouserpin\n");
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


	// loads Luna KeyStore (calls C_Login).
	private static void loadKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		KeyStore lunaKeyStore = KeyStore.getInstance("Luna");
		lunaKeyStore.load(new ByteArrayInputStream(("tokenlabel:"+slotLabel+"\nusertype:CKU_CRYPTO_USER\n").getBytes()), cryptoUserPassword.toCharArray());
		System.out.println("Luna KeyStore loaded successfully.");
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			cryptoUserPassword = args[1];
			addLunaProvider();
			loadKeyStore();
		} catch(ArrayIndexOutOfBoundsException aioe) {
			printUsage();
			System.exit(1);
		} catch(Exception exception) {
			System.out.println("\nERROR: " + exception.getMessage());
		}
	}
}
