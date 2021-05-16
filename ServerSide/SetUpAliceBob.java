import java.util.*;
import java.io.*;
import java.lang.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;
import java.math.BigInteger; 
import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException; 
import java.security.SecureRandom;
import java.util.Random;


class Util {

	public static final BigInteger TWO = BigInteger.valueOf(2);
	public static final BigInteger THREE = BigInteger.valueOf(3);
	public static final BigInteger FOUR = BigInteger.valueOf(4);
	public static final BigDecimal TWO_DEC = BigDecimal.valueOf(2);

	private static final SecureRandom rand = new SecureRandom();

	public static BigInteger convertStringToBigInt(String message) {
		BigInteger retVal = BigInteger.valueOf(0);
		for (int i = 0; i < message.length(); i++) {
			int charVal = message.charAt(message.length() - (i + 1));
			// Add the value by offsetting by 3 decminal places
			retVal = retVal.add(BigInteger.valueOf(charVal).multiply(
					BigInteger.TEN.pow(i * 3)));
		}
		return retVal;
	}

	public static String convertBigIntToString(BigInteger value) {
		StringBuffer result = new StringBuffer();
		String val = value.toString();
		for (int i = 0; i < Math.ceil((double) val.length() / (double) 3); i++) {
			int end = val.length() - (i * 3);
			int start = (end - 3 < 0) ? 0 : end - 3;
			result.insert(0, (char) Integer.valueOf(val.substring(start, end))
					.intValue());
		}

		return result.toString();
	}

	public static BigInteger randomBigInteger(BigInteger min, BigInteger max) {
		BigInteger n;
		do {
			n = randomBigInteger(min.bitLength(), max.bitLength());
		} while (n.compareTo(min) <= 0 || n.compareTo(max) >= 0);
		return n;
	}

	public static BigInteger randomBigInteger(int minBits, int maxBits) {
		// Chose a random length
		int bits = rand.nextInt(maxBits - minBits + 1) + minBits;
		BigInteger n = new BigInteger(bits, rand);
		// Make sure we didn't get a random bigint outside range
		while (n.bitLength() <= minBits && n.bitLength() >= maxBits) {
			n = new BigInteger(bits, rand);
		}
		return n;
	}

	
	public static BigInteger getSqRoot(BigInteger bigint) {
		BigDecimal n = new BigDecimal(bigint);
		int scale = bigint.toString().length() / 2;
		int length = bigint.toString().length();
		if ((length % 2) == 0)
			length--;
		length /= 2;

		BigDecimal guess = BigDecimal.ONE.movePointRight(length);
		BigDecimal lastGuess = BigDecimal.ZERO;
		BigDecimal error = BigDecimal.ZERO;

		boolean more = true;
		int iterations = 0;
		while (more) {
			lastGuess = guess;
			guess = n.divide(guess, scale, BigDecimal.ROUND_HALF_UP);
			guess = guess.add(lastGuess);
			guess = guess.divide(TWO_DEC, scale, BigDecimal.ROUND_HALF_UP);
			error = n.subtract(guess.multiply(guess));
			if (++iterations >= 50) {
				more = false;
			} else if (lastGuess.equals(guess)) {
				more = error.abs().compareTo(BigDecimal.ONE) >= 0;
			}
		}
		return guess.toBigInteger();
	}
}


class FastExponentiation {

	public static BigInteger fastExponentiation(BigInteger base,
			BigInteger exponent, BigInteger modulus) {
		return recurseFastExponentiation(base, exponent, modulus,
				BigInteger.ONE);
	}

	private static BigInteger recurseFastExponentiation(BigInteger base,
			BigInteger exponent, BigInteger modulus, BigInteger result) {

		if (exponent.equals(BigInteger.ZERO)) {
			return result;
		} else if (exponent.mod(BigInteger.valueOf(2)).equals(BigInteger.ONE)) {
			return recurseFastExponentiation(base,
					exponent.subtract(BigInteger.ONE), modulus,
					base.multiply(result).mod(modulus));
		} else {
			return recurseFastExponentiation(base.multiply(base).mod(modulus),
					exponent.divide(BigInteger.valueOf(2)), modulus, result);
		}
	}
}






class MillerRabin {

	private static int attempts = 20;

	public static boolean testStrongPrime(BigInteger n) {
		// If p is 0, 1, or an event number return false
		if (n.equals(BigInteger.ZERO) || n.equals(BigInteger.ONE)
				|| n.mod(Util.TWO).equals(BigInteger.ZERO))
			return false;

		// 2 is prime so return true
		if (n.equals(Util.TWO))
			return true;

		// Generate 2 ^ r * m
		int r = 0;
		BigInteger m = n.subtract(BigInteger.ONE);
		BigInteger nMinusOne = n.subtract(BigInteger.ONE);
		while (m.mod(Util.TWO).equals(BigInteger.ZERO)) {
			m = m.divide(Util.TWO);
			r++;
		}

		for (int i = 0; i < attempts; i++) {
			// Pick a random number
			BigInteger b = Util.randomBigInteger(BigInteger.ONE,
					n.subtract(BigInteger.ONE));

			// Compute b ^ m mod n
			BigInteger z = FastExponentiation.fastExponentiation(b, m, n);

			// If y = 1 mod n or -1 mod n skip and try next random number
			if (!z.equals(BigInteger.ONE) && !z.equals(nMinusOne)) {
				boolean isWitness = false;
				for (int j = 0; j < r; j++) {
					z = FastExponentiation.fastExponentiation(b, Util.TWO
							.pow(j).multiply(m), n);

					// n is a composite
					if (z.equals(BigInteger.ONE))
						return false;

					// b is a witness to n primality
					if (z.equals(nMinusOne)) {
						isWitness = true;
						break;
					}
				}
				if (!isWitness) {
					return false;
				}
			}
		}
		return true;
	}

}


class PrimitiveRootSearch {
    
    public static BigInteger primitiveRootSearch(BigInteger p) throws Exception {
		if (p == null || !MillerRabin.testStrongPrime(p))
			throw new Exception("Invalid p for primitive root search");

		// Find prime factors of p-1 once
		BigInteger n = p.subtract(BigInteger.ONE);
		Set<BigInteger> factors = findPrimeFactors(n);

		// Try to find the primitive root by starting at random number
		BigInteger g = Util.randomBigInteger(Util.TWO,
				n.subtract(BigInteger.ONE));
		while (!checkPrimitiveRoot(g, p, n, factors)) {
			g = g.add(BigInteger.ONE);
		}
		return g;
	}

	private static boolean checkPrimitiveRoot(BigInteger g, BigInteger p,
			BigInteger n, Set<BigInteger> factors) {
		// Run g^(n / "each factor) mod p
		// If the is 1 mod p then g is not a primitive root
		Iterator<BigInteger> i = factors.iterator();
		while (i.hasNext()) {
			if (FastExponentiation.fastExponentiation(g, n.divide(i.next()), p)
					.equals(BigInteger.ONE)) {
				return false;
			}
		}
		return true;
	}

	private static Set<BigInteger> findPrimeFactors(BigInteger n) {
		// Set is unique
		Set<BigInteger> factors = new HashSet<BigInteger>();
		for (BigInteger i = BigInteger.valueOf(2); i.compareTo(n) <= 0; i = i
				.add(BigInteger.ONE)) {
			while (n.mod(i).equals(BigInteger.ZERO)) {
				// Add y to factors and decrease n
				factors.add(i);
				n = n.divide(i);
				// This should speed things up a bit for very large numbers!
				if (MillerRabin.testStrongPrime(n))
					return factors;
			}
		}
		return factors;
	}
        
    
}




public class SetUpAliceBob {
    
    private Formatter x;
    
    public static String encryptThisString(String input) 
    { 
        try { 
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 
  
            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
  
            // Add preceding 0s to make it 32 bit 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
  
            // return the HashText 
            return hashtext; 
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
    
    public void openFile()
    {
        try{
            // "C:\\Users\\Asus\\Desktop\\netbeansJava\\ServerSide\\src\\dhParamaters.txt"
            String workingDir = System.getProperty("user.dir");
            x = new Formatter( workingDir +"\\dhParamaters.txt");
        }catch(Exception e){
            
            System.out.println("ERROR occured .....");
            
        }
    }
    
    public void write(BigInteger p, BigInteger g, String ep)
    {
        x.format("%s %s %s", p.toString(),g.toString(),ep);
    }
    
    public void close()
    {
        x.close();
    }
    
    public static void main(String[] args) throws Exception  {  
        
        SetUpAliceBob setup = new SetUpAliceBob();
        //String commonPassword = "stayw!thm3";
        String commonPassword = "six666";
        BigInteger number = new BigInteger(32,new Random());
        BigInteger prime = number.nextProbablePrime();
        
        System.out.println("Prime value : " + prime);
        
        PrimitiveRootSearch prs = new PrimitiveRootSearch();
        
        BigInteger generator = prs.primitiveRootSearch(prime);
        
        System.out.println("G(Generator) value : " + generator );
        
        //generate the hashpassword
        //HashPassword hp = new HashPassword();        
        String encryptedPassword = encryptThisString( commonPassword );        
        System.out.println("Encrypted Password : " + encryptedPassword);
        
        //send the text file to Host(Alice)
        setup.openFile();
        setup.write(prime, generator, encryptedPassword);
        setup.close();
        
    }
    
}
