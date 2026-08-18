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
	- This sample demonstrates how to generate a DES-3 key using LunaProvider.
	- Key generated using this sample is ephemeral, i.e. a session key.
	- This sample would fail with 0x70 (CKR_MECHANISM_INVALID) when used with a FIPS mode enabled Luna HSM.

*/


import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.exception.*;

public class GenerateDES3Key {
	private static LunaSlotManager slotManager = null;
	private static String slotPassword = null;
	private static String slotLabel = null;
	private static SecretKey des3Key = null;
	private static final String PROVIDER = "LunaProvider";


	// Prints the correct syntax to execute this sample.
	private static void printUsage() {
		System.out.println(" [ GenerateDES3Key ]\n");
		System.out.println("Usage-");
		System.out.println("java GenerateDES3Key <slot_label> <crypto_officer_password>\n");
		System.out.println("Example -");
		System.out.println("java GenerateDES3Key myPartition userpin\n");
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


	// generates des-3 key.
	private static void generateKey() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("DESede","LunaProvider");
		des3Key = keyGen.generateKey();
		if(des3Key!=null) {
			System.out.println("DES-3 key generated.");
		}
	}

	public static void main(String args[]) {
		try {
			slotLabel = args[0];
			slotPassword = args[1];
			slotManager = LunaSlotManager.getInstance();

			if(slotManager.findSlotFromLabel(slotLabel)!=-1) { // checks if the slot number is correct.
				addLunaProvider();
				slotManager.login(slotLabel, slotPassword); // Performs C_Login
				System.out.println("LOGIN: SUCCESS");
				generateKey();
			} else {
				System.out.println("ERROR: Slot with label " + slotLabel + " not found.");
				System.exit(1);
			}

			LunaSlotManager.getInstance().logout(); // Performs C_Logout
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
