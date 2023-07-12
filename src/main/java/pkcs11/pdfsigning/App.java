package pkcs11.pdfsigning;

import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.CertificateUtil;
import com.itextpdf.signatures.ICrlClient;
import com.itextpdf.signatures.CrlClientOnline;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IOcspClient;
import com.itextpdf.signatures.OcspClientBouncyCastle;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.ITSAClient;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.TSAClientBouncyCastle;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStore.CallbackHandlerProtection;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class App {

    public static final String[] RESULT_FILES = new String[] {
            "signed_using_token.pdf"
    };
    
    public static void main( String[] args ) throws IOException, GeneralSecurityException {
    
    	String currentDirectory = System.getProperty("user.dir");
    	String SRC = currentDirectory + "\\pdf\\mydoc.pdf";
    	String DEST = currentDirectory + "\\pdf\\";
    	
    	File file = new File(DEST);   	
    	file.mkdirs();
    	
    	System.out.println("Enter the token password: ");
    	Scanner sc = new Scanner(System.in);
    	String in = sc.next();
    	
        char[] pass = in.toCharArray();

        // Specify the correct path to the CRYPTOKI (PKCS#11) DLL.
        //String dllPath = "E:/user_data/workspace/usb/trustoken/trustokenP11Lib.dll";  //Trustoken
        String dllPath = "C:/Windows/System32/eps2003csp11v2.dll";    //epass 2003 Auto
        //String dllPath = "C:/Windows/System32/SignatureP11.dll";     //Prox Key
        //String dllPath = "C:/Windows/System32/Watchdata/PROXKey CSP India V2.0/WDPKCS.dll";
        
        CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
        initArgs.flags = 0;
        
        long[] slots = getSlotsWithTokens(dllPath);
        
        if (slots != null) {
        	String config = "name=ikey4000\n" +
                    "library=" + dllPath;
        	//+ "\n" +
              //      "slotListIndex = " + slots[0];
        	
        	ByteArrayInputStream bais = new ByteArrayInputStream(config.getBytes());
            Provider providerPKCS11 = new SunPKCS11(bais);
            Security.addProvider(providerPKCS11);
            
        	BouncyCastleProvider providerBC = new BouncyCastleProvider();
            Security.addProvider(providerBC);
            
            //CallbackHandlerProtection chp = new CallbackHandlerProtection(new MyGuiCallbackHandler() {});
            //Builder builder = Builder.newInstance("PKCS11", null, chp);
            //KeyStore keyStore = builder.getKeyStore();
            
            KeyStore ks = KeyStore.getInstance("PKCS11");
            ks.load(null, pass);
            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, null);
            
            Certificate[] chain = ks.getCertificateChain(alias);
            
            IOcspClient ocspClient = new OcspClientBouncyCastle(null);
            ITSAClient tsaClient = null;
            
            //long slotID = slots[0];
            
            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = (X509Certificate) chain[i];
                String tsaUrl = CertificateUtil.getTSAURL(cert);
                if (tsaUrl != null) {
                    tsaClient = new TSAClientBouncyCastle(tsaUrl);
                    break;
                }
            }
            
            List<ICrlClient> crlList = new ArrayList<ICrlClient>();
            crlList.add(new CrlClientOnline(chain));
            
            new App().sign(SRC, DEST + RESULT_FILES[0], chain, pk,
                    DigestAlgorithms.SHA256, providerPKCS11.getName(), PdfSigner.CryptoStandard.CMS,
                    "Document", "Raipur", crlList, ocspClient, tsaClient, 0);
        } else {
            System.out.println("An exception was encountered while getting token slot's indexes.");
        }
    }
    
    public void sign(String src, String dest, Certificate[] chain, PrivateKey pk,
            String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
            String reason, String location, Collection<ICrlClient> crlList,
            IOcspClient ocspClient, ITSAClient tsaClient, int estimatedSize)
            		throws GeneralSecurityException, IOException {
    	
    	PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties().useAppendMode());
        
        // Create the signature appearance
        Rectangle rect = new Rectangle(36, 648, 200, 100);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        
        appearance
        	.setReason(reason)
        	.setLocation(location)

	        // Specify if the appearance before field is signed will be used
	        // as a background for the signed field. The "false" value is the default value.
	        .setReuseAppearance(false)
	        .setPageRect(rect)
	        .setPageNumber(1);
        
        signer.setFieldName("sig");
        
        IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, crlList, ocspClient, tsaClient, estimatedSize, subfilter);
    }
    
    // Method returns a list of token slot's indexes
    public static long[] getSlotsWithTokens(String libraryPath) {
    	
    	CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
  
    	String functionList = "C_GetFunctionList";
    	
    	initArgs.flags = 0;
        PKCS11 tmpPKCS11 = null;
        long[] slotList = null;
        
        try {
            try {
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, false);
            } catch (IOException ex) {
                ex.printStackTrace();
                return null;
            }
        } catch (Exception e) {
            try {
                initArgs = null;
                tmpPKCS11 = PKCS11.getInstance(libraryPath, functionList, initArgs, true);
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
        
        try {
            slotList = tmpPKCS11.C_GetSlotList(true);

            for (long slot : slotList) {
                CK_TOKEN_INFO tokenInfo = tmpPKCS11.C_GetTokenInfo(slot);
                System.out.println("slot: " + slot + "\nmanufacturerID: "
                        + String.valueOf(tokenInfo.manufacturerID) + "\nmodel: "
                        + String.valueOf(tokenInfo.model));
            }
        } catch (Throwable ex) {
            ex.printStackTrace();
        }

        return slotList;
    }
}

    
    
    
    
    
    
    
    