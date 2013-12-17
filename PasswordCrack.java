import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;


public class PasswordCrack 
{
	static int count;
	static int mangleCount;
	static long start1;												// the start time for a particular password
	static boolean timeLimit;										// indicates whether time limit for a password has been reached
	public static final int TIME_LIMIT = 120000;
	static HashMap <String, String> passwordsCracked = new HashMap <String, String> ();
	public static void main(String args[]) throws IOException 
	{
		count = 0;
		if (args.length != 2) {
			System.out.println("Usage: PassWordCrack inputDictionaryFile passwordFile");
		} 
		else {
			long start = System.currentTimeMillis(); // begin timer
			String dictionaryFile= args[0];
			String passwordFile = args[1];
			Dictionary dict = new Dictionary();		// create the dictionary object
//			Dictionary dict2 = new Dictionary();	// for one mangle
//			Dictionary dict3 = new Dictionary();	// for two mangles
			
			BufferedReader dictReader = new BufferedReader (new FileReader(dictionaryFile));
			dict.readDictionary(dictReader);
			
			BufferedReader passwordReader = new BufferedReader (new FileReader(passwordFile));
			
			// need to split password file line by semicolons
			String delimiter = ":";
			String passwordLine;
			String [] temp;
			while ((passwordLine = passwordReader.readLine()) != null)
			{
				timeLimit = false;
				mangleCount = 0;								// reset mangleCount for each password
				start1 = System.currentTimeMillis();		//timing for individual passwordline
				String username, saltPassword, name;
				System.out.println(passwordLine);
				temp = passwordLine.split(delimiter);		//split password line to obtain name and encrypted password of 13 characters
															//first 2 characters are salt, next 11 are actual password
				
				username = temp[0];									//username
				saltPassword = temp[1];								//salt + password to compare encrypted passwords with
				String salt = saltPassword.substring(0,2);			//salt (first 2 characters of total password)
				String password = saltPassword.substring(2);		//password
				
				// split name into first and last name to add to dictionary
				name = temp[4];
				String[] temp2 = name.split(" ");
				String firstName = temp2[0];
				String lastName = temp2[1];
				
				System.out.println("Name is: " + name);
				System.out.println("Salt is: " + salt);	
				System.out.println("Encrypted Password is: " + password);
				
				dict.addWord(0, username);							//add username to dictionary at front
				dict.addWord(0, firstName);							//firstName
				dict.addWord(0, lastName);							//lastName
				
				//perform encryption of possible passwords and compare with saltPassword
				/* 0 or single mangles */
				if (noMangle(username, saltPassword, salt, dict)) {
					printPassWordTime(start1);
					continue;
				}
				if (mangleOnce (username, saltPassword, salt, dict)) {
					printPassWordTime(start1);
					continue;
				}
				
				if (mangleCount == 0) ++mangleCount;
				System.out.println("About to mangle twice, mangleCount is: " + mangleCount);
				/* 2 Mangles */
				if (mangleOnce (username, saltPassword, salt, dict)) {
					printPassWordTime(start1);
					continue;
				}
				
				if (mangleCount == 1) ++mangleCount;
				System.out.println("About to mangle thrice, mangleCount is: " + mangleCount);
				/* 3 Mangles */
				if (mangleOnce (username, saltPassword, salt, dict)) {
					printPassWordTime(start1);
					continue;
				}
				
				// print time if failed
				System.out.println("Password not found.");
				printPassWordTime(start1);
			}
			
			long end = System.currentTimeMillis();
			System.out.println("Number of passwords cracked: " + count);
			for (Map.Entry<String, String> entry : passwordsCracked.entrySet()) {
			    System.out.println("Password cracked for user: " + entry.getKey() + ", password = " + entry.getValue());
			}
			System.out.println("Total time taken ms: " + (end-start));
			dictReader.close();
			passwordReader.close();
		}
	}

	/* guess password using dictionary with no mangles */
	private static boolean noMangle (String user, String encryptedPassword, String salt, Dictionary dict)
	{
		String tempEnc;
		ArrayList<String> dictionary = dict.getDictionary();
		for (String s: dictionary)
		{
			tempEnc = jcrypt.crypt (salt, s);
			if (checkPassword(user, encryptedPassword, s, tempEnc)) return true;
		}
		return false;
	}
	
	/* delete first character or last character */
	private static boolean deleteMangle(String user, String encryptedPassword, String salt, Dictionary dict) {
		String temp, tempEnc;
		ArrayList<String> dictionary = dict.getDictionary();
		long end1 = System.currentTimeMillis();
		if (end1 - start1 >= TIME_LIMIT)
		{
			timeLimit = true;
			return false;
		}
		// stop checking this password if time threshold has passed (30000ms = 30 seconds)
		for (String s: dictionary)
		{
			// if string length is 8 or less, then deleting from end will change algorithm
			if (s.length() <= 8)
			{
				/* delete last character */
				temp = deleteLast(s);
				if (mangleCount == 0)
				{
					tempEnc = jcrypt.crypt (salt, temp);
					if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
				}
				else if (mangleCount == 1) {
					if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
				}
				else if (mangleCount == 2)
				{
					String t;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = duplicate(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverseReflect(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = lower(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = upper(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = capitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = nCapitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteFirst(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteLast(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle1(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle2(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = prepend(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

					}
					if (temp.length() < 8)
					{
						for (char i = 0x20; i <= 0x7E; i++)
						{
							t = append(temp, i);
							if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						}
					}
				}
			}
			/* delete first character */
			temp = deleteFirst(s);
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle1(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle2(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
		}
		return false;
	}
	
	/* Reverse string, reflect string, reverse then reflect string, duplicate string */
	private static boolean reverseReflectDupMangle(String user, String encryptedPassword, String salt, Dictionary dict) {
		String temp, tempEnc;
		ArrayList<String> dictionary = dict.getDictionary();
		long end1 = System.currentTimeMillis();
		if (end1 - start1 >= TIME_LIMIT)
		{
			timeLimit = true;
			return false;
		}
		for (String s: dictionary)
		{
			/* reversed string */
			temp = reverse(s);										//reversed string
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle1(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle2(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
			
			// only perform duplicate and reflect if string is less than 8 characters
			if (s.length() < 8)
			{
				/* reflect the string */
				temp = reflect(s);
				if (mangleCount == 0)
				{
					tempEnc = jcrypt.crypt (salt, temp);
					if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
				}
				else if (mangleCount == 1) {
					if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
				}
				else if (mangleCount == 2)
				{
					String t;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = duplicate(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverseReflect(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = lower(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = upper(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = capitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = nCapitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteFirst(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteLast(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle1(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle2(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = prepend(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

					}
					if (temp.length() < 8)
					{
						for (char i = 0x20; i <= 0x7E; i++)
						{
							t = append(temp, i);
							if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						}
					}
				}
				
				/* duplicate the string */										//append original string to itself		
				temp = duplicate(s);
				if (mangleCount == 0)
				{
					tempEnc = jcrypt.crypt (salt, temp);
					if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
				}
				else if (mangleCount == 1){
					if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
				}
				else if (mangleCount == 2)
				{
					String t;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = duplicate(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverseReflect(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = lower(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = upper(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = capitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = nCapitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteFirst(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteLast(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle1(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle2(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = prepend(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

					}
					if (temp.length() < 8)
					{
						for (char i = 0x20; i <= 0x7E; i++)
						{
							t = append(temp, i);
							if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						}
					}
				}
				
				/* reverse then reflect string*/
				temp = reverseReflect(s);
				if (mangleCount == 0)
				{
					tempEnc = jcrypt.crypt (salt, temp);
					if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
				}
				else if (mangleCount == 1) {
					if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
				}
				else if (mangleCount == 2)
				{
					String t;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = duplicate(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverse(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = reverseReflect(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = lower(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = upper(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = capitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = nCapitalize(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteFirst(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = deleteLast(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle1(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					t = toggle2(temp);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = prepend(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

					}
					if (temp.length() < 8)
					{
						for (char i = 0x20; i <= 0x7E; i++)
						{
							t = append(temp, i);
							if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						}
					}
				}
			}
		}
		return false;
	}
	
	/* perform case transformations */
	private static boolean caseMangle(String user, String encryptedPassword, String salt, Dictionary dict) {
		String temp, tempEnc;
		ArrayList<String> dictionary = dict.getDictionary();
		long end1 = System.currentTimeMillis();
		if (end1 - start1 >= TIME_LIMIT)
		{
			timeLimit = true;
			return false;
		}
		for (String s: dictionary)
		{
			/* capitalize first letter */
			temp = capitalize(s);
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle1(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle2(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
			
			/* all caps */
			temp = upper(s);
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle1(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle2(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
			
			/* all lower case */
			temp = lower(s);
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle1(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle2(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
			
			/* ncapitalize */
			temp = nCapitalize(s);
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle1(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = toggle2(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
			
			/* toggle case */
			temp = toggle1(s);
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, true)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
			
			temp = toggle2(s);
			if (mangleCount == 0)
			{
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			else if (mangleCount == 1) {
				if (checkAllMangles(user, salt, encryptedPassword, temp, true)) return true;
			}
			else if (mangleCount == 2)
			{
				String t;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = duplicate(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverse(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = reverseReflect(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = lower(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = upper(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = capitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = nCapitalize(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteFirst(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				t = deleteLast(temp);
				if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
				for (char i = 0x20; i <= 0x7E; i++)
				{
					t = prepend(temp, i);
					if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

				}
				if (temp.length() < 8)
				{
					for (char i = 0x20; i <= 0x7E; i++)
					{
						t = append(temp, i);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
					}
				}
			}
		}
		return false;
	}
	
	/* guess password using dictionary with either a prepend or append mangle */
	private static boolean prependAppendMangle (String user, String encryptedPassword, String salt, Dictionary dict)
	{
		String temp, tempEnc;
		ArrayList<String> dictionary = dict.getDictionary();
		long end1 = System.currentTimeMillis();
		if (end1 - start1 >= TIME_LIMIT)
		{
			timeLimit = true;
			return false;
		}
		for (String s: dictionary)
		{
			// if length is already at max for algorithm, no need to check for appending character
			if (s.length() >= 8)
			{
				// loop through printable characters
				for (char i = 0x20; i <= 0x7E; i++)
				{
					/* prepend printable character */
					temp = prepend(s, i);
					if (mangleCount == 0)
					{
						tempEnc = jcrypt.crypt (salt, temp);
						if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
					}
					else if (mangleCount == 1) {
						if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
					}
					else if (mangleCount == 2)
					{
						String t;
						t = reverse(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = duplicate(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = reverse(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = reverseReflect(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = lower(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = upper(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = capitalize(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = nCapitalize(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = deleteFirst(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = deleteLast(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = toggle1(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = toggle2(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						for (char j = 0x20; j <= 0x7E; j++)
						{
							t = prepend(temp, j);
							if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

						}
						if (temp.length() < 8)
						{
							for (char j = 0x20; j <= 0x7E; j++)
							{
								t = append(temp, j);
								if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
							}
						}
					}
				}
			}
			
			//if length is less than max, then perform both append and prepend
			else 
			{
				// loop through printable characters
				for (char i = 0x20; i <= 0x7E; i++)
				{
					/* append printable character */
					temp = append(s, i);
					if (mangleCount == 0)
					{
						tempEnc = jcrypt.crypt (salt, temp);
						if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
					}
					else if (mangleCount == 1) {
						if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
					}
					else if (mangleCount == 2)
					{
						String t;
						t = reverse(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = duplicate(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = reverse(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = reverseReflect(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = lower(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = upper(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = capitalize(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = nCapitalize(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = deleteFirst(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = deleteLast(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = toggle1(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = toggle2(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						for (char j = 0x20; j <= 0x7E; j++)
						{
							t = prepend(temp, j);
							if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

						}
						if (temp.length() < 8)
						{
							for (char j = 0x20; j <= 0x7E; j++)
							{
								t = append(temp, j);
								if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
							}
						}
					}
					
					/* prepend printable character */
					temp = prepend(s, i);
					if (mangleCount == 0)
					{
						tempEnc = jcrypt.crypt (salt, temp);
						if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
					}
					else if (mangleCount == 0) {
						if (checkAllMangles(user, salt, encryptedPassword, temp, false)) return true;
					}
					else if (mangleCount == 2)
					{
						String t;
						t = reverse(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = duplicate(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = reverse(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = reverseReflect(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = lower(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = upper(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = capitalize(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = nCapitalize(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = deleteFirst(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = deleteLast(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = toggle1(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						t = toggle2(temp);
						if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
						for (char j = 0x20; j <= 0x7E; j++)
						{
							t = prepend(temp, j);
							if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;

						}
						if (temp.length() < 8)
						{
							for (char j = 0x20; j <= 0x7E; j++)
							{
								t = append(temp, j);
								if (checkAllMangles(user, salt, encryptedPassword, t, false)) return true;
							}
						}
					}
				}
			}
		}
		return false;
	}
	
	/* Perform mangle on dict depending on count */
	private static boolean mangleOnce (String username, String encryptedPassword, String salt, 
			Dictionary dict)
	{	
		if (timeLimit) return false;
		if (deleteMangle(username, encryptedPassword, salt, dict)) return true;
		if (timeLimit) return false;
		if (reverseReflectDupMangle(username, encryptedPassword, salt, dict)) return true;
		if (timeLimit) return false;
		if (caseMangle(username, encryptedPassword, salt, dict)) return true;
		if (timeLimit) return false;
		if (prependAppendMangle(username, encryptedPassword, salt, dict)) return true;		//perform prepend/append last since it has inner loop
		return false;
	}
	
	/* check if encrypted password equals encrypted password guess, returns boolean to indicate */
	private static boolean checkPassword (String user, String encryptedPassword, String guessPass, String guessEncrypted)
	{
		if (guessEncrypted.equals(encryptedPassword))
		{
			System.out.println("Password is: " + guessPass);
			passwordsCracked.put(user, guessPass);
			count++;
			mangleCount++;
			return true;
		}
		return false;
	}
	
	/* run a string through all mangles and check if it is password */
	private static boolean checkAllMangles (String user, String salt, String encryptedPassword, String guessPass, 
			boolean toggle)
	{
		long end1 = System.currentTimeMillis();
		if (end1-start1 >= TIME_LIMIT)
		{
			timeLimit = true;
			return false;
		}
		String temp, tempEnc;
		int length = guessPass.length();
		temp = deleteFirst(guessPass);
		tempEnc = jcrypt.crypt (salt, temp);
		if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
		
		temp = reverse(guessPass);
		tempEnc = jcrypt.crypt (salt, temp);
		if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
		
		temp = upper(guessPass);
		tempEnc = jcrypt.crypt (salt, temp);
		if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
		temp = lower(guessPass);
		tempEnc = jcrypt.crypt (salt, temp);
		if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;

		temp = capitalize(guessPass);
		tempEnc = jcrypt.crypt (salt, temp);
		if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
		temp = nCapitalize(guessPass);
		tempEnc = jcrypt.crypt (salt, temp);
		if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
		//no point in toggling case if it has already been done
		if (!toggle){
			temp = toggle1(guessPass);
			tempEnc = jcrypt.crypt (salt, temp);
			if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			temp = toggle2(guessPass);
			tempEnc = jcrypt.crypt (salt, temp);
		}
		if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
		if (length < 9)
		{
			temp = deleteLast(guessPass);
			tempEnc = jcrypt.crypt (salt, temp);
			if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			if (length < 8)
			{
				temp = duplicate(guessPass);
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
				temp = reflect(guessPass);
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
				temp = reverseReflect(guessPass);
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;
			}
			
		}

		
		for (char i = 0x20; i <= 0x7E; i++)
		{
			temp = prepend(guessPass, i);
			tempEnc = jcrypt.crypt (salt, temp);
			if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;	
		}
		if (guessPass.length() < 8)
		{
			for (char i = 0x20; i <= 0x7E; i++)
			{
				temp = append(guessPass, i);
				tempEnc = jcrypt.crypt (salt, temp);
				if (checkPassword(user, encryptedPassword, temp, tempEnc)) return true;	
			}
		}

		
		return false;
		
	}
	
	/* print the time it took to find a password */
	private static void printPassWordTime (long start1)
	{
		long end1 = System.currentTimeMillis();
		System.out.println("One password time, ms: " + (end1-start1));
		System.out.println();
	}
	
	/* Helper methods to perform one mangle on a StringBuffer: StringBuffer used for performance reasons */
	// reverse a stringbuffer
	private static String reverse(String s)
	{
		StringBuilder sb = new StringBuilder(s);
		return sb.reverse().toString();
	}
	// duplicate a string
	private static String duplicate(String s)
	{
		return s + s;
	}
	// reflect a string
	private static String reflect(String s)
	{
		return s + reverse(s);
	}
	// reverse, then reflect string
	private static String reverseReflect(String s)
	{
		return reverse(s) + s;
	}
	// uppercase string
	private static String upper(String s)
	{
		return s.toUpperCase();
	}
	// lowercase string
	private static String lower(String s)
	{
		return s.toLowerCase();
	}
	// capitalize string
	private static String capitalize(String s)
	{
		String upper = upper(s);
		String lower = lower(s);
		return upper.charAt(0) + lower.substring(1,s.length());
	}
	// ncapitalize string
	private static String nCapitalize(String s)
	{
		String upper = upper(s);
		String lower = lower(s);
		return lower.charAt(0) + upper.substring(1,s.length());
	}
	// toggle case with first lower
	private static String toggle1(String s)
	{
		String upper = upper(s);
		String lower = lower(s);
		StringBuilder toggle = new StringBuilder();				//toggle case starting with upper
		for (int i = 0; i < s.length(); i++)
		{
			if (i % 2 == 0)
				toggle.append(upper.charAt(i));
			else 
				toggle.append(lower.charAt(i));
		}
		return toggle.toString();
	}
	// toggle case with first upper
	private static String toggle2(String s)
	{
		String upper = upper(s);
		String lower = lower(s);
		StringBuilder toggle = new StringBuilder();				//toggle case starting with lower
		for (int i = 0; i < s.length(); i++)
		{
			if (i % 2 == 0)
				toggle.append(lower.charAt(i));
			else 
				toggle.append(upper.charAt(i));
		}
		return toggle.toString();
	}
	// delete first character
	private static String deleteFirst(String s)
	{
		
		if (s.length() <= 1) return s;
		return s.substring(1);
	}
	// delete last character
	private static String deleteLast(String s)
	{
		if (s.length() <= 1) return s;
		return s.substring(0, s.length()-1);
	}
	// prepend
	private static String prepend(String s, char c)
	{
		return c + s;
	}
	// append
	private static String append(String s, char c)
	{
		return s + c;
	}
}
