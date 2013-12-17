import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

/* Class to represent the dictionary in use for password checking */

public class Dictionary 
{
	ArrayList<String> dictList;
	public Dictionary ()
	{
		dictList = new ArrayList<String>();
	}
	
	public ArrayList<String> getDictionary ()
	{
		return dictList;
	}
	
	/* read in the dictionary file */
	public void readDictionary (BufferedReader dictReader) throws IOException
	{
		String line;
		while ((line = dictReader.readLine()) != null)
		{
			addWord(line);
		}
	}
	
	/* add word to dictionary */
	public void addWord (String word)
	{
		dictList.add(word);
	}
	
	public void addWord (int index, String word)
	{
		dictList.add(index, word);
	}
	
	public void sortDictionary ()
	{
		Collections.sort(dictList);
	}
	
	/* print out dictionary list */
	public void printDictionary ()
	{
		for (String s: dictList)
			System.out.println(s);
	}
}
