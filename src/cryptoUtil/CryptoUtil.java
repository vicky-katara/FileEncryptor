

/*
 * Source: http://stackoverflow.com/questions/23561104/how-to-encrypt-and-decrypt-string-with-my-passphrase-in-java-pc-not-mobile-plat
 */
package cryptoUtil;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
/*** Encryption and Decryption of String data; PBE(Password Based Encryption and Decryption)
* @author Vikram
*/
public class CryptoUtil 
{
    Cipher ecipher;
    Cipher dcipher;
    // 8-byte Salt
    byte[] salt = {
        (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
        (byte) 0x56, (byte) 0x39, (byte) 0xE3, (byte) 0x09
    };
    // Iteration count
    int iterationCount = 19;
    public CryptoUtil() 
    { 

    }

    /**
     * 
     * @param secretKey Key used to encrypt data
     * @param plainText Text input to be encrypted
     * @return Returns encrypted text
     * 
     */
    
    public byte[] encrypt_n(String secretKey, String plainText) 
            throws NoSuchAlgorithmException, 
            InvalidKeySpecException, 
            NoSuchPaddingException, 
            InvalidKeyException,
            InvalidAlgorithmParameterException, 
            UnsupportedEncodingException, 
            IllegalBlockSizeException, 
            BadPaddingException{
        //Key generation for enc and desc
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);        
         // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

        //Enc process
        ecipher = Cipher.getInstance(key.getAlgorithm());
        ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);      
        String charSet="UTF-8";       
        byte[] in = plainText.getBytes(charSet);
        byte[] out = ecipher.doFinal(in);
        //String encStr=new sun.misc.BASE64Encoder().encode(out);
        //System.out.println("Byte Rep: "+Arrays.toString(out));
        return out;
    }
     /**     
     * @param secretKey Key used to decrypt data
     * @param encryptedText encrypted text input to decrypt
     * @return Returns plain text after decryption
     */
    
    public String decrypt_n(String secretKey, byte[] encryptedText)
     throws NoSuchAlgorithmException, 
            InvalidKeySpecException, 
            NoSuchPaddingException, 
            InvalidKeyException,
            InvalidAlgorithmParameterException, 
            UnsupportedEncodingException, 
            IllegalBlockSizeException, 
            BadPaddingException, 
            IOException{
         //Key generation for enc and desc
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);        
         // Prepare the parameter to the ciphers
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
        //Decryption process; same key will be used for decr
        dcipher=Cipher.getInstance(key.getAlgorithm());
        dcipher.init(Cipher.DECRYPT_MODE, key,paramSpec);
        //byte[] enc = new sun.misc.BASE64Decoder().decodeBuffer(new String(encryptedText));
        byte[] utf8 = dcipher.doFinal(encryptedText);
        String charSet="UTF-8";     
        String plainStr = new String(utf8, charSet);
        return plainStr;
    }    
    
    public static void main(String[] args) throws Exception {
        CryptoUtil cryptoUtil=new CryptoUtil();
        String key="654321";   
        String plain="Specifically, I aim to develop capabilities which would help me discover the associations and understand the patterns and trends within sentiment data. In my opinion, Context-based sentiment analysis would begin influencing the field of analytics in the near future. The sentiment found within comments, feedback or evaluations provide indicators for useful insights. Effective context based sentiment analysis can help various industries better understand their customer preferences. Moreover, the growing impact of social media provides an effective source for reliable sentiment data.";
        //String enc=cryptoUtil.encrypt(key, plain);
        byte[] enc = cryptoUtil.encrypt_n(key, plain);
        System.out.println("Original text: "+plain);
        System.out.println("Encrypted text: "+Arrays.toString(enc));       
        //String plainAfter=cryptoUtil.decrypt(key, enc);
        String plainAfter=cryptoUtil.decrypt_n(key, enc);
        System.out.println("Original text after decryption: "+plainAfter);
    }
}