package signerverifier

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuMswW3iu7PR/rWTQjlhVmUsPK7rF
k2s4SO3XbQ2GG2alm289SUUpmBAuVxvT8muYQ8HC/QzixzyTACTXsBDjQg==
-----END PUBLIC KEY-----`

// to run locally, we need to impersonate the GCP service account
// gcloud auth application-default login --impersonate-service-account attest-kms-test@attest-kms-test.iam.gserviceaccount.com

// func TestGCPKMS_Signer(t *testing.T) {
// 	// create a new signer
// 	ctx := context.Background()
// 	ref := "projects/attest-kms-test/locations/us-west1/keyRings/attest-kms-test/cryptoKeys/test-signing-key/cryptoKeyVersions/1"
// 	signer, err := GetGCPSigner(ctx, ref)
// 	require.NoError(t, err)
// 	msg := []byte("hello world")
// 	hash := util.SHA256(msg)

// 	// sign message digest
// 	sig, err := signer.Sign(ctx, hash)
// 	require.NoError(t, err)
// 	assert.NotEmpty(t, sig)
// 	// get Key ID from signer
// 	keyId, err := signer.KeyID()
// 	require.NoError(t, err)
// 	assert.NotEmpty(t, keyId)
// 	publicKey, err := Parse([]byte(publicKeyPEM))
// 	require.NoError(t, err)
// 	// verify payload ecdsa signature
// 	ok := ecdsa.VerifyASN1(publicKey, hash, sig)
// 	assert.True(t, ok)
// }
