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
        - This sample demonstrates how dynamically insert LunaProvider at a specied location of Java Security.
	- LunaProvider would be inserted at position #3 of Java security.

*/

import java.security.Provider;
import java.security.Security;
import com.safenetinc.luna.provider.LunaProvider;

public class InsertLunaProvider {

	private static final int PROVIDER_POSITION = 3;
	// Display list of all providers.
	private static void listProviders() {
		Provider []providers = Security.getProviders();
		for(Provider provider:providers) {
			System.out.println(provider);
		}
	}

	// Insert LunaProvider at #3 position.
	private static void insertLunaProvider() {
		Security.insertProviderAt(new LunaProvider(), PROVIDER_POSITION);
	}

	public static void main(String args[]) {

		System.out.println("----- BEFORE ADDING LUNA PROVIDER -----");
		listProviders();

		System.out.println("\n----- AFTER ADDING LUNA PROVIDER -----");
		insertLunaProvider();
		listProviders();

		System.out.println();
	}
}

