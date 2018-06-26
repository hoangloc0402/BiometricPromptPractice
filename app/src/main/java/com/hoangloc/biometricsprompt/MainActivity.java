package com.hoangloc.biometricsprompt;

import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.Toast;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

public class MainActivity extends AppCompatActivity {
    private static final String KEY_NAME = "TEST_KEY";
    private BiometricPrompt biometricPrompt;
    private String toBeSignedMessage;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (!isSupportBiometricPrompt())
            return;

        findViewById(R.id.buttonRegister).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Signature signature;
                try {
                    KeyPair keyPair = generateKeyPair(KEY_NAME, true);
                    toBeSignedMessage = new StringBuilder()
                            .append(Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.URL_SAFE))
                            .append(":")
                            .append(KEY_NAME)
                            .append(":")
                            .append("1511849")
                            .toString();
                    signature = initSignature(KEY_NAME);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                biometricPrompt = new BiometricPrompt.Builder(getApplicationContext())
                        .setDescription("Register description")
                        .setTitle("Register Tittle")
                        .setSubtitle("Register Subtitle")
                        .setNegativeButton(
                                "Cancel",
                                getMainExecutor(),
                                new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialogInterface, int i) {
                                        Toast.makeText(getApplicationContext(), "Canceled Register FingerPrint", Toast.LENGTH_SHORT).show();
                                    }
                                })
                        .build();
                CancellationSignal cancellationSignal = getCancellationSignal();
                BiometricPrompt.AuthenticationCallback authenticationCallback = getAuthenticationCallback();

                // Show biometric prompt
                if (signature != null) {
                    //Log.i(TAG, "Show biometric prompt");
                    biometricPrompt.authenticate(
                            new BiometricPrompt.CryptoObject(signature),
                            cancellationSignal,
                            getMainExecutor(),
                            authenticationCallback);
                }
            }
        });


        findViewById(R.id.buttonAuthenticate).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

            }
        });
    }

    private CancellationSignal getCancellationSignal() {
        // With this cancel signal, we can cancel biometric prompt operation
        CancellationSignal cancellationSignal = new CancellationSignal();
        cancellationSignal.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            @Override
            public void onCancel() {
                //handle cancel result
                //Log.i(TAG, "Canceled");
            }
        });
        return cancellationSignal;
    }

    private BiometricPrompt.AuthenticationCallback getAuthenticationCallback() {
        // Callback for biometric authentication result
        return new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
            }

            @Override
            public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                super.onAuthenticationHelp(helpCode, helpString);
            }

            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                //Log.i(TAG, "onAuthenticationSucceeded");
                super.onAuthenticationSucceeded(result);
                Signature signature = result.getCryptoObject().getSignature();
                try {
                    signature.update(toBeSignedMessage.getBytes());
                    String signatureString = Base64.encodeToString(signature.sign(), Base64.URL_SAFE);
                    // Normally, ToBeSignedMessage and Signature are sent to the server and then verified
                    //Log.i(TAG, "Message: " + toBeSignedMessage);
                    //Log.i(TAG, "Signature (Base64 EncodeD): " + signatureString);
                    Toast.makeText(getApplicationContext(), toBeSignedMessage + "     :" + signatureString, Toast.LENGTH_SHORT).show();
                } catch (SignatureException e) {
                    throw new RuntimeException();
                }
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
            }
        };
    }



    private boolean isSupportBiometricPrompt() {
        PackageManager packageManager = this.getPackageManager();
        if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            return true;
        }
        return false;
    }

    private KeyPair generateKeyPair(String keyName, boolean invalidatedByBiometricEnrollment) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyName,
                KeyProperties.PURPOSE_SIGN);

        builder.setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"));
        builder.setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512);

        builder.setUserAuthenticationRequired(true);
        builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);

        keyPairGenerator.initialize(builder.build());
        return keyPairGenerator.generateKeyPair();
    }

    @Nullable
    private KeyPair getKeyPair(String keyName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(keyName)) {

            PublicKey publicKey = keyStore.getCertificate(keyName).getPublicKey();

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyName, null);

            return new KeyPair(publicKey, privateKey);
        }
        return null;
    }

    @Nullable
    private Signature initSignature(String keyName) throws Exception {
        KeyPair keyPair = getKeyPair(keyName);

        if (keyPair != null) {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            return signature;
        }
        return null;
    }

}
