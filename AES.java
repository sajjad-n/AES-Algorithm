import java.util.*;

class AES {
	static final byte[] ESBox = {
			99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118,
			-54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64,
			-73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21,
			4, -57, 35, -61, 24, -106, 5, -102, 7, 18, -128, -30, -21, 39, -78, 117,
			9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124,
			83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49,
			-48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, 127, 80, 60, -97, -88,
			81, -93, 64, -113, -110, -99, 56, -11, -68, -74, -38, 33, 16, -1, -13, -46,
			-51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115,
			96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37,
			-32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121,
			-25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8,
			-70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118,
			112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98,
			-31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33,
			-116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22 };
	static final byte[] DSBox = {
			82, 9, 106, -43, 48, 54, -91, 56, -65, 64, -93, -98, -127, -13, -41, -5,
			124, -29, 57, -126, -101, 47, -1, -121, 52, -114, 67, 68, -60, -34, -23, -53,
			84, 123, -108, 50, -90, -62, 35, 61, -18, 76, -107, 11, 66, -6, -61, 78,
			8, 46, -95, 102, 40, -39, 36, -78, 118, 91, -94, 73, 109, -117, -47, 37,
			114, -8, -10, 100, -122, 104, -104, 22, -44, -92, 92, -52, 93, 101, -74, -110,
			108, 112, 72, 80, -3, -19, -71, -38, 94, 21, 70, 87, -89, -115, -99, -124,
			-112, -40, -85, 0, -116, -68, -45, 10, -9, -28, 88, 5, -72, -77, 69, 6,
			-48, 44, 30, -113, -54, 63, 15, 2, -63, -81, -67, 3, 1, 19, -118, 107,
			58, -111, 17, 65, 79, 103, -36, -22, -105, -14, -49, -50, -16, -76, -26, 115,
			-106, -84, 116, 34, -25, -83, 53, -123, -30, -7, 55, -24, 28, 117, -33, 110,
			71, -15, 26, 113, 29, 41, -59, -119, 111, -73, 98, 14, -86, 24, -66, 27,
			-4, 86, 62, 75, -58, -46, 121, 32, -102, -37, -64, -2, 120, -51, 90, -12,
			31, -35, -88, 51, -120, 7, -57, 49, -79, 18, 16, 89, 39, -128, -20, 95,
			96, 81, 127, -87, 25, -75, 74, 13, 45, -27, 122, -97, -109, -55, -100, -17,
			-96, -32, 59, 77, -82, 42, -11, -80, -56, -21, -69, 60, -125, 83, -103, 97,
			23, 43, 4, 126, -70, 119, -42, 38, -31, 105, 20, 99, 85, 33, 12, 125 };
	static final byte[] rcon = {
			0,
			1, 2, 4, 8, 16, 32,
			64, -128, 27, 54, 108, -40,
			-85, 77, -102, 47, 94, -68,
			99, -58, -105, 53, 106, -44,
			-77, 125, -6, -17, -59, -111 };
	static final int[] shift = {0, 1, 2, 3};
    int numRounds, traceLevel = 0;
    String traceInfo = "";
	static final int ROUNDS = 14, BLOCK_SIZE = 16;
	byte[][] Ke;
	byte[][] Kd;
	static final int
	COL_SIZE = 4,     
	NUM_COLS = BLOCK_SIZE / COL_SIZE,
	ROOT = 0x11B;
	static final int[] alog = new int[256];
	static final int[] log =  new int[256];
	static { // for multiplying in the field GF(2^8)
		int i, j;
		alog[0] = 1;
		for (i = 1; i < 256; i++) {
			j = (alog[i-1] << 1) ^ alog[i-1];
			if ((j & 0x100) != 0) j ^= ROOT;
			alog[i] = j;
		}
		for (i = 1; i < 255; i++) log[alog[i]] = i;
	}
	
	public static void main (String[] args) {
		AES aes = new AES();
		String data = aes.getText();
		String key = aes.getKey();
		aes.setKey(static_stringToByteArray(key));
		String encryptedText = aes.Encrypt(data); 
		String encryptedHexText = Util.toHEX(encryptedText.getBytes()).replace(" ", "");
		String unencryptedText = aes.Decrypt(encryptedText); 
		aes.showResults(data, key, encryptedText, encryptedHexText, unencryptedText);
	}
	
	public static int getRounds (int keySize) {
		switch (keySize) {
		case 16:    
			return 10;
		case 24:    
			return 12;
		default:    
			return 14;
		}
	}

	static final int mul (int a, int b) { 
		// Multiply two elements of GF(2^8).
		return (a != 0 && b != 0) ?alog[(log[a & 0xFF] + log[b & 0xFF]) % 255] : 0;
	}

	public byte[] encrypt(byte[] plain) {
		byte [] a = new byte[BLOCK_SIZE];    // state variable
		byte [] ta = new byte[BLOCK_SIZE];    // temp state variable
		byte [] Ker;
		int    i, j, k, row, col;

		traceInfo = "";
		if (traceLevel > 0) traceInfo = "encryptAES(" + Util.toHEX1(plain) + ")";

		// verification
		if (plain == null)
			throw new IllegalArgumentException("Empty plaintext");
		if (plain.length != BLOCK_SIZE)
			throw new IllegalArgumentException("Incorrect plaintext length");

		// copy plaintext bytes into state 
		Ker = Ke[0];
		for (i = 0; i < BLOCK_SIZE; i++)    a[i] = (byte)(plain[i] ^ Ker[i]);
		if (traceLevel > 2)
			traceInfo += "n  R0 (Key = "+Util.toHEX1(Ker)+")ntAK = "+Util.toHEX1(a);
		else if (traceLevel > 1)
			traceInfo += "n  R0 (Key = "+Util.toHEX1(Ker)+")t = "+Util.toHEX1(a);

		for (int r = 1; r < numRounds; r++) {
			Ker = Ke[r];            // get session keys for this round
			if (traceLevel > 1)    traceInfo += "n  R"+r+" (Key = "+Util.toHEX1(Ker)+")t";

			// SubBytes(state)
			for (i = 0; i < BLOCK_SIZE; i++) ta[i] = ESBox[a[i] & 0xFF];
			if (traceLevel > 2)    traceInfo += "ntSB = "+Util.toHEX1(ta);

			// ShiftRows(state)
			for (i = 0; i < BLOCK_SIZE; i++) {
				row = i % COL_SIZE;
				k = (i + (shift[row] * COL_SIZE)) % BLOCK_SIZE;    // get shifted byte index
				a[i] = ta[k];
			}
			if (traceLevel > 2)    traceInfo += "ntSR = "+Util.toHEX1(a);

			// MixColumns(state)
			for (col = 0; col < NUM_COLS; col++) {
				i = col * COL_SIZE;
				ta[i]   = (byte)(mul(2,a[i]) ^ mul(3,a[i+1]) ^ a[i+2] ^ a[i+3]);
				ta[i+1] = (byte)(a[i] ^ mul(2,a[i+1]) ^ mul(3,a[i+2]) ^ a[i+3]);
				ta[i+2] = (byte)(a[i] ^ a[i+1] ^ mul(2,a[i+2]) ^ mul(3,a[i+3]));
				ta[i+3] = (byte)(mul(3,a[i]) ^ a[i+1] ^ a[i+2] ^ mul(2,a[i+3]));
			}
			if (traceLevel > 2)    traceInfo += "ntMC = "+Util.toHEX1(ta);

			// AddRoundKey(state)
			for (i = 0; i < BLOCK_SIZE; i++)    a[i] = (byte)(ta[i] ^ Ker[i]);
			if (traceLevel > 2)    traceInfo += "ntAK";
			if (traceLevel > 1)    traceInfo += " = "+Util.toHEX1(a);
		}
		
		Ker = Ke[numRounds];            // get session keys
		if (traceLevel > 1)    traceInfo += "n  R"+numRounds+" (Key = "+Util.toHEX1(Ker)+")t";

		// SubBytes(state)
		for (i = 0; i < BLOCK_SIZE; i++) a[i] = ESBox[a[i] & 0xFF];
		if (traceLevel > 2)    traceInfo += "ntSB = "+Util.toHEX1(a);

		// ShiftRows(state)
		for (i = 0; i < BLOCK_SIZE; i++) {
			row = i % COL_SIZE;
			k = (i + (shift[row] * COL_SIZE)) % BLOCK_SIZE;    // get shifted byte index
			ta[i] = a[k];
		}
		if (traceLevel > 2)    traceInfo += "ntSR = "+Util.toHEX1(a);

		// AddRoundKey(state)
		for (i = 0; i < BLOCK_SIZE; i++)    a[i] = (byte)(ta[i] ^ Ker[i]);
		if (traceLevel > 2)    traceInfo += "ntAK";
		if (traceLevel > 1)    traceInfo += " = "+Util.toHEX1(a)+"n";
		if (traceLevel > 0)    traceInfo += " = "+Util.toHEX1(a)+"n";
		return (a);
	}

	public byte[] decrypt(byte[] cipher) {
		byte [] a = new byte[BLOCK_SIZE];    // AES state variable
		byte [] ta = new byte[BLOCK_SIZE];    // AES temp state variable
		byte [] Kdr; 
		int    i, j, k, row, col;

		traceInfo = "";               
		if (traceLevel > 0) traceInfo = "decryptAES(" + Util.toHEX1(cipher) + ")";

		// verification
		if (cipher == null)
			throw new IllegalArgumentException("Empty ciphertext");
		if (cipher.length != BLOCK_SIZE)
			throw new IllegalArgumentException("Incorrect ciphertext length");

		Kdr = Kd[0];
		for (i = 0; i < BLOCK_SIZE; i++)    a[i] = (byte)(cipher[i] ^ Kdr[i]);
		if (traceLevel > 2)
			traceInfo += "n  R0 (Key = "+Util.toHEX1(Kdr)+")nt AK = "+Util.toHEX1(a);
		else if (traceLevel > 1)
			traceInfo += "n  R0 (Key = "+Util.toHEX1(Kdr)+")t = "+Util.toHEX1(a);

		for (int r = 1; r < numRounds; r++) {
			Kdr = Kd[r];            // get session keys for this round
			if (traceLevel > 1)    traceInfo += "n  R"+r+" (Key = "+Util.toHEX1(Kdr)+")t";

			// InvShiftRows(state)
			for (i = 0; i < BLOCK_SIZE; i++) {
				row = i % COL_SIZE;
				k = (i + BLOCK_SIZE - (shift[row] * COL_SIZE)) % BLOCK_SIZE;
				ta[i] = a[k];
			}
			if (traceLevel > 2)    traceInfo += "ntISR = "+Util.toHEX1(ta);

			// InvSubBytes(state) 
			for (i = 0; i < BLOCK_SIZE; i++) a[i] = DSBox[ta[i] & 0xFF];
			if (traceLevel > 2)    traceInfo += "ntISB = "+Util.toHEX1(a);

			// AddRoundKey(state)
			for (i = 0; i < BLOCK_SIZE; i++)    ta[i] = (byte)(a[i] ^ Kdr[i]);
			if (traceLevel > 2)    traceInfo += "nt AK = "+Util.toHEX1(ta);

			// InvMixColumns(state) 
			for (col = 0; col < NUM_COLS; col++) {
				i = col * COL_SIZE;        // start index for this col
				a[i]   = (byte)(mul(0x0e,ta[i]) ^ mul(0x0b,ta[i+1]) ^ mul(0x0d,ta[i+2]) ^ mul(0x09,ta[i+3]));
				a[i+1] = (byte)(mul(0x09,ta[i]) ^ mul(0x0e,ta[i+1]) ^ mul(0x0b,ta[i+2]) ^ mul(0x0d,ta[i+3]));
				a[i+2] = (byte)(mul(0x0d,ta[i]) ^ mul(0x09,ta[i+1]) ^ mul(0x0e,ta[i+2]) ^ mul(0x0b,ta[i+3]));
				a[i+3] = (byte)(mul(0x0b,ta[i]) ^ mul(0x0d,ta[i+1]) ^ mul(0x09,ta[i+2]) ^ mul(0x0e,ta[i+3]));
			}
			if (traceLevel > 2)    traceInfo += "ntIMC";
			if (traceLevel > 1)    traceInfo += " = "+Util.toHEX1(a);
		}

		Kdr = Kd[numRounds];
		if (traceLevel > 1)    traceInfo += "n  R"+numRounds+" (Key = "+Util.toHEX1(Kdr)+")t";

		// InvShiftRows(state)
		for (i = 0; i < BLOCK_SIZE; i++) {
			row = i % COL_SIZE;
			// get shifted byte index
			k = (i + BLOCK_SIZE - (shift[row] * COL_SIZE)) % BLOCK_SIZE;
			ta[i] = a[k];
		}
		if (traceLevel > 2)    traceInfo += "ntISR = "+Util.toHEX1(a);

		// InvSubBytes(state)
		for (i = 0; i < BLOCK_SIZE; i++) ta[i] = DSBox[ta[i] & 0xFF];
		if (traceLevel > 2)    traceInfo += "ntISB = "+Util.toHEX1(a);

		// AddRoundKey(state)
		for (i = 0; i < BLOCK_SIZE; i++)    a[i] = (byte)(ta[i] ^ Kdr[i]);
		if (traceLevel > 2)    traceInfo += "nt AK";
		if (traceLevel > 1)    traceInfo += " = "+Util.toHEX1(a)+"n";
		if (traceLevel > 0)    traceInfo += " = "+Util.toHEX1(a)+"n";
		return (a);
	}

	public void setKey(byte[] key) {
		final int BC = BLOCK_SIZE / 4;
		final int Klen = key.length;
		final int Nk = Klen / 4;

		int i, j, r;

		traceInfo = "";   
		if (traceLevel > 0) traceInfo = "setKey(" + Util.toHEX1(key) + ")n";

		// set master number of rounds given size of this key
		numRounds = getRounds(Klen);
		final int ROUND_KEY_COUNT = (numRounds + 1) * BC;

		//holds 1 of the 4 bytes [b0 b1 b2 b3] in each word w
		byte[] w0 = new byte[ROUND_KEY_COUNT];
		byte[] w1 = new byte[ROUND_KEY_COUNT];
		byte[] w2 = new byte[ROUND_KEY_COUNT];
		byte[] w3 = new byte[ROUND_KEY_COUNT];

		Ke = new byte[numRounds + 1][BLOCK_SIZE]; // encryption
		Kd = new byte[numRounds + 1][BLOCK_SIZE]; // decryption

		for (i=0, j=0; i < Nk; i++) {
			w0[i] = key[j++]; w1[i] = key[j++]; w2[i] = key[j++]; w3[i] = key[j++];
		}

		// implement key expansion algorithm
		byte t0, t1, t2, t3, old0;        
		for (i = Nk; i < ROUND_KEY_COUNT; i++) {
			t0 = w0[i-1]; t1 = w1[i-1]; t2 = w2[i-1]; t3 = w3[i-1];   
			if (i % Nk == 0) {
				old0 = t0;         
				t0 = (byte)(ESBox[t1 & 0xFF] ^ rcon[i/Nk]); 
				t1 = (byte)(ESBox[t2 & 0xFF]);
				t2 = (byte)(ESBox[t3 & 0xFF]);  
				t3 = (byte)(ESBox[old0 & 0xFF]);
			}
			else if ((Nk > 6) && (i % Nk == 4)) {
				t0 = ESBox[t0 & 0xFF]; t1 = ESBox[t1 & 0xFF]; t2 = ESBox[t2 & 0xFF]; t3 = ESBox[t3 & 0xFF];
			}
			w0[i] = (byte)(w0[i-Nk] ^ t0);
			w1[i] = (byte)(w1[i-Nk] ^ t1);
			w2[i] = (byte)(w2[i-Nk] ^ t2);
			w3[i] = (byte)(w3[i-Nk] ^ t3);
		}

		// copy values into en/decrypt session arrays
		for (r = 0, i = 0; r < numRounds + 1; r++) {    
			for (j = 0; j < BC; j++) { 
				Ke[r][4*j] = w0[i];
				Ke[r][4*j+1] = w1[i];
				Ke[r][4*j+2] = w2[i];
				Ke[r][4*j+3] = w3[i];
				Kd[numRounds - r][4*j] = w0[i];
				Kd[numRounds - r][4*j+1] = w1[i];
				Kd[numRounds - r][4*j+2] = w2[i];
				Kd[numRounds - r][4*j+3] = w3[i];
				i++;
			}
		}
	}

	public static String static_byteArrayToString(byte[] data) {
		String res = "";
		StringBuffer sb = new StringBuffer();
		for(int i=0; i<data.length; i++) {
			int n = (int) data[i];
			if(n<0) n += 256;
			sb.append((char) n);
		}
		res = sb.toString();
		return res;
	}

	public static byte[] static_stringToByteArray(String s){
		byte[] temp = new byte[s.length()];
		for(int i=0;i<s.length();i++){
			temp[i] = (byte) s.charAt(i);
		}
		return temp;
	}

	public static String static_intArrayToString(int[]t){
		StringBuffer sb = new StringBuffer();
		for(int i=0;i<t.length;i++){
			sb.append((char)t[i]);
		}
		return sb.toString();
	}

	public String _cryptAll(String data, int mode)  {
		AES aes = this;
		if(data.length()/16 > ((int) data.length()/16)) {
			int rest = data.length()-((int) data.length()/16)*16;
			for(int i=0; i<rest; i++)
				data += " ";
		}
		int nParts = (int) data.length()/16;
		byte[] res = new byte[data.length()];
		String partStr = "";
		byte[] partByte = new byte[16];
		for(int p=0; p<nParts; p++) {
			partStr = data.substring(p*16, p*16+16);
			partByte = static_stringToByteArray(partStr);
			if(mode==1) partByte = aes.encrypt(partByte);
			if(mode==2) partByte = aes.decrypt(partByte);
			for(int b=0; b<16; b++)
				res[p*16+b] = partByte[b];
		}
		return static_byteArrayToString(res);
	}

	public String Encrypt(String data) {
		while((data.length() % 32) != 0) data += " ";
		return _cryptAll(data, 1);
	}
	
	public String Decrypt(String data) {
		return _cryptAll(data, 2).trim();
	}

	private final static class Util {
		public static final char[] HEX_DIGITS = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

		public static byte[] shortToByte (short[] sa) {
			int length = sa.length;
			byte[] ba = new byte[length * 2];
			for (int i = 0, j = 0, k; i < length; ) {
				k = sa[i++];
				ba[j++] = (byte)((k >>> 8) & 0xFF);
				ba[j++] = (byte)( k        & 0xFF);
			}
			return (ba);
		}

		public static short[] byteToShort (byte[] ba) {
			int length = ba.length;
			short[] sa = new short[length / 2];
			for (int i = 0, j = 0; j < length / 2; ) {
				sa[j++] = (short)(((ba[i++] & 0xFF) <<  8) |
						((ba[i++] & 0xFF)      ));
			}
			return (sa);
		}

		public static int[] byteToInt (byte[] ba) {
			int length = ba.length;
			int[] ia = new int[length / 4];
			for (int i = 0, j = 0; j < length / 4; ) {
				ia[j++] = (((ba[i++] & 0xFF) << 24) |
						((ba[i++] & 0xFF) << 16) |
						((ba[i++] & 0xFF) <<  8) |
						((ba[i++] & 0xFF)      ));
			}
			return (ia);
		}

		public static String toHEX (byte[] ba) {
			int length = ba.length;
			char[] buf = new char[length * 3];
			for (int i = 0, j = 0, k; i < length; ) {
				k = ba[i++];
				buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
				buf[j++] = HEX_DIGITS[ k        & 0x0F];
				buf[j++] = ' ';
			}
			return new String(buf);
		}
		
		public static String toHEX1 (byte[] ba) {
			int length = ba.length;
			char[] buf = new char[length * 2];
			for (int i = 0, j = 0, k; i < length; ) {
				k = ba[i++];
				buf[j++] = HEX_DIGITS[(k >>> 4) & 0x0F];
				buf[j++] = HEX_DIGITS[ k        & 0x0F];
			}
			return new String(buf);
		}
	}
	
	public String getText() {
		System.out.println("Enter Text: ");
	    return new Scanner(System.in).nextLine();
	}
	    
	public String getKey() {
		String key;
		do {
			System.out.println("\nEnter key: ");
			key = new Scanner(System.in).nextLine();
	         
			// Verification
	        if (key.length() != 16 && key.length() != 24 & key.length() != 32) 
	        	System.out.println("AES just uses 128/192/256-bit (16/24/32 byte) keys!");
	        } while (key.length() != 16 && key.length() != 24 && key.length() != 32);
		return key;
	}
	  
	public void showResults(String data, String key, String encryptedText, String encryptedHexText, String unencryptedText) {
		System.out.println("\nText: " + data + " ----- size: " + data.length() + " bytes");
		System.out.println("Key: " + key + " ----- size: " + key.length() + " bytes");
	    System.out.println("Encrypted Text: " + encryptedText + " ----- size: " + encryptedText.length() + " bytes");
		System.out.println("HEX Encrypted Text: " + encryptedHexText + " ----- size: " + encryptedHexText.length() + " bytes");
		System.out.println("Unencrypted Text: " + unencryptedText + " ----- size: " + unencryptedText.length() + " bytes");
    }

}