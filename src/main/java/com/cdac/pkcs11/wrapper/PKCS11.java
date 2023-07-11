package com.cdac.pkcs11.wrapper;


import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_MECHANISM;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.CK_SLOT_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11Exception;

public class PKCS11 {
	
	static {
		System.loadLibrary("p11cdacwrapper");
	}

	public native int initializeLibrary(String lipath);
	public native int deinitializeLibrary();
	public native int C_Initialize(CK_C_INITIALIZE_ARGS pInitArgs)  throws PKCS11Exception;
	public native CK_INFO C_GetInfo();
	public native int C_Finalize(Object pReserved);
	public native long[] C_GetSlotList(boolean jTokenPresent) throws PKCS11Exception;
	public native CK_SLOT_INFO C_GetSlotInfo (long jSlotID) throws PKCS11Exception;
	public native CK_TOKEN_INFO C_GetTokenInfo (long jSlotID);
	public native long C_OpenSession(long jSlotID, long jFlags, Object jApplication, Object jNotify) throws PKCS11Exception;
	public native CK_SESSION_INFO C_GetSessionInfo(long jSessionHandle);
	public native void C_Login(long jSessionHandle, long jUserType, char[] jPin) throws PKCS11Exception;
	public native long C_CreateObject(long jSessionHandle, CK_ATTRIBUTE[] jTemplate);
	public native void C_DestroyObject(long jSessionHandle, long jObjectHandle);
	public native long C_GetObjectSize(long jSessionHandle, long jObjectHandle);
	public native void C_FindObjectsInit(long jSessionHandle, CK_ATTRIBUTE[] jTemplate)  throws PKCS11Exception;
	public native long[] C_FindObjects(long jSessionHandle,long jMaxObjectCount)  throws PKCS11Exception;
	public native void C_FindObjectsFinal(long jSessionHandle)  throws PKCS11Exception;
	public native void C_GetAttributeValue(long jSessionHandle, long jObjectHandle, CK_ATTRIBUTE[] jTemplate);
	public native void C_SignInit(long jSessionHandle, CK_MECHANISM jMechanism, long jKeyHandle) throws PKCS11Exception;
	public native byte[] C_Sign(long jSessionHandle, byte[] jData) throws PKCS11Exception;
	public native byte[] C_GenerateRandom(long jSessionHandle, long RandomLen) throws PKCS11Exception;
	public native void C_DigestInit(long jSessionHandle, CK_MECHANISM jMechanism);
	public native byte[] C_Digest(long jSessionHandle, byte[] jDigest);
	public native long[] C_GenerateKeyPair(long jSessionHandle, CK_MECHANISM jMechanism,  CK_ATTRIBUTE[] jPublicKeyTemplate,  CK_ATTRIBUTE[] jPrivateKeyTemplate);
}
