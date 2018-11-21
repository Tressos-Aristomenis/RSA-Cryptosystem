import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 * @author Aris
 */
public class RSA {
    public static void main(String[] args) {
       long startTime = System.nanoTime();
	   
	   final int BITS = Integer.parseInt(args[0]);
	   final BigInteger p = generatePrime(BITS);
	   final BigInteger q = generatePrime(BITS);
	   final BigInteger n = p.multiply(q);
	   final BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
	   final BigInteger e = get_encryption_key(phi);
	   final BigInteger d = get_decryption_key(e, phi);
//  ------------------------------------------------------------------------------------------	   
	   final BigInteger message = generateMessage(n);
	   final BigInteger encrypted_text = encrypt(e, message, n);
	   final BigInteger decrypted_text = decrypt(d, encrypted_text, n);
	   
	   
	   System.out.println("Public key: [e = " + e + ", n = " + n + "]");
	   System.out.println("Private key: [d = " + d + ", n = " + n + "]"); 
	   System.out.println("Plain text: " + message);
	   System.out.println("Encrypted text: " + encrypted_text);
	   System.out.println("Decrypted text: " + decrypted_text);
	   
	   long endTime   = System.nanoTime();
	   long totalTime = endTime - startTime;
	   System.out.println("RSA encryption finished in: " + totalTime / 1000000000.0 + "seconds.");
    }
	
	private static BigInteger get_encryption_key(BigInteger phi) {
	   BigInteger key = BigInteger.ZERO;
	   BigInteger counter = new BigInteger("2");
	   
	   while (counter.compareTo(phi) < 0) {
		   if (gcd(phi, counter).equals(BigInteger.ONE)) {
			   key = counter;
			   break;
		   }
		   
		   counter = counter.add(BigInteger.ONE);
	   }
	   
	   return key;
   }
   
   private static BigInteger get_decryption_key(BigInteger e, BigInteger phi) {
	   return e.modInverse(phi);
   }
   
   private static BigInteger encrypt(BigInteger e, BigInteger plain, BigInteger n) {
	   return plain.modPow(e, n);
   }
   
   private static BigInteger decrypt(BigInteger d, BigInteger cipher, BigInteger n) {
	   return cipher.modPow(d, n);
   }
   
   private static BigInteger gcd(BigInteger a, BigInteger b) {
	   BigInteger dividend = (a.compareTo(b) >= 0) ? a : b;
	   BigInteger divisor = (a.compareTo(b) <= 0) ? a : b;
	   
	   while (!divisor.equals(BigInteger.ZERO)) {
		   BigInteger remainder = dividend.mod(divisor);
		   dividend = divisor;
		   divisor = remainder;
	   }
	   
	   return dividend;
   }
	
	private static BigInteger generatePrime(int bits) {
		SecureRandom ran = new SecureRandom();
		BigInteger prime = new BigInteger(bits, ran);

		while (true) {
			if (prime.isProbablePrime(1)) {
				break;
			}

			prime = prime.subtract(new BigInteger("1"));
		}
		
		return prime;
	}

	private static BigInteger generateMessage(BigInteger n) {
		BigInteger message = BigInteger.ZERO;
		
		while (true) {
			message = new BigInteger(n.bitLength(), new SecureRandom());
			if (message.compareTo(n) < 0) {
				break;
			}
		}
		
		return message;
	}
}
