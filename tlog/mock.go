package tlog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
)

const (
	UseMockTL = true

	TestEntry = `{"body":"eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI5Zjg2ZDA4MTg4NGM3ZDY1OWEyZmVhYTBjNTVhZDAxNWEzYmY0ZjFiMmIwYjgyMmNkMTVkNmMxNWIwZjAwYTA4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJQUlyVUZGUzBIYmNzZjc5L08yajVXdHl2R2Vvd1NVSXpZcDlBM2IwWnREVUFpQVQxZU42ZjFyVmVWa011REFlN3dxWkJ2bE5LY2VsajNVVDNmaWhyQjZSY2c9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVSlZla05DSzJGQlJFRm5SVU5CWjBWQ1RVRnZSME5EY1VkVFRUUTVRa0ZOUTAxQk9IaEVWRUZNUW1kT1ZrSkJUVlJDU0ZKc1l6TlJkMGhvWTA0S1RXcE5lRTFxU1ROTlZHdDVUWHBWTlZkb1kwNU5hbEY0VFdwSk1rMVVhM2xOZWxVMVYycEJVRTFSTUhkRGQxbEVWbEZSUkVWM1VqQmFXRTR3VFVacmR3cEZkMWxJUzI5YVNYcHFNRU5CVVZsSlMyOWFTWHBxTUVSQlVXTkVVV2RCUlVRMFZpdFNSV2g0SzJGeFYwZzNlV3hOVFVSSVlXaE9UVzVOVEZOUFNsQXZDamxyUVcwNWJIQXJNMjF4V1ZSQmFGVlNjbUUyVDBRMVVYZzRXbUprSzJWMVVIbFFhemw1SzNjdloxZEhSRUk1ZW00dlNXd3hTMDVIVFVWUmQwUm5XVVFLVmxJd1VFRlJTQzlDUVZGRVFXZGxRVTFDVFVkQk1WVmtTbEZSVFUxQmIwZERRM05IUVZGVlJrSjNUVVJOUVhkSFFURlZaRVYzUlVJdmQxRkRUVUZCZHdwRWQxbEVWbEl3VWtKQlozZENiMGxGWkVkV2VtUkVRVXRDWjJkeGFHdHFUMUJSVVVSQlowNUtRVVJDUjBGcFJVRTNOMjFFTDFSbVJtRlJVemxrWlhRMENqbFhaRk41YURKT1VTOUZiMVJtYVVGdFFtaHVWblpEVTNSUVowTkpVVU1yZDNSdllpOU9iMUp4T0c5cU4wZDNibTVKYUZKVGRDOVJNbmtyVXpoUkwzSUthRkpVYW5GaE9HZExRVDA5Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn19fX0=","integratedTime":1703705039,"logID":"c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d","logIndex":59674396,"verification":{"inclusionProof":{"checkpoint":"rekor.sigstore.dev - 2605736670972794746\n55510966\nJCi1O53Xmdi9lXnui4Q5SQ+MJSMnWr1Bxn+Q2Qf22tU=\nTimestamp: 1703705040158839214\n\n— rekor.sigstore.dev wNI9ajBFAiAXgtjFDVqCSgiSP04TQzELrz4+EyBwyYVL2EEULTCy0AIhAI9peLU76ZUD1tvU8qvzBJBo77IYD1rc+A1MPc35AeVK\n","hashes":["fb77ee213b48f4b18dc81c6e634c570abf99b257713561f174f2e0f4c039af67","6cb113bbefadecbbb8b89b1c08232438a6125071790b6a062cff8c1ccfdcb91e","6fbe1424e264e4590ca502d671b7a036c87f7a90d1f57534b98eb781144160bf","077b606720a6478200f6c3ed08a68e9b01b1cae192cb120888ddcc95521601bd","b6f8e8bc21ae0cde82b92422a4b4f37b28a43185821e468a4e65b6c79ed8f5b7","89332533fac54e9bc68c7353c42f6ebb9fe38039f67910332ff95082072068d4","0814d6f707a75fb3334bab14ab5466bd8b9a64ae7be7cd4d53a428c64932bc66","e883e826f10329c63a4a2ed21156037a050df43b9d74079296beac6968ed4150","d79230703257b7e4a8a61b032b6980d1a0bdbc7ae96ca838b525b3751785fe48","2f4a77e5288462cd3b75084d37f1502dcbe0943d18dd95cb247fc1ebbabc0aad","38562c253d3536d0d00e3547c880b6b0251a25ac69605b50c9eaa1a27186cc7a","9dea192350ff8b3c0f5ccda38261cb38ebd61869281c3928912332d1144e0a04","2c4d25ba59aa573ab2c79c2d3cd9e1d74789b10632432724d63112ce50b44874","98c486feb5d87092a78a46c4b5be04868654900affc2e86ffb20074dc73a883a","6969c49bd73f19bf28a5eaeabd331ddd60502defb2cd3d96e17b741c80adec6c"],"logIndex":55510965,"rootHash":"2428b53b9dd799d8bd9579ee8b8439490f8c2523275abd41c67f90d907f6dad5","treeSize":55510966},"signedEntryTimestamp":"MEUCIQCG9PRI8PcvtJyE9pbcculZipze6NEWR1Nk8EYocto3BwIgYu5gqgjW80HMjSjUxUNJLp0wlVTesnJCeByUBySc59w="}}`
)

type MockTLConfig struct {
	IntegratedTime time.Time
}

type MockTLOption func(*MockTLConfig)

func WithIntegratedTime(t time.Time) MockTLOption {
	return func(cfg *MockTLConfig) {
		cfg.IntegratedTime = t
	}
}

func GetMockTL(opts ...MockTLOption) TransparencyLog {
	cfg := &MockTLConfig{
		IntegratedTime: time.Now(), // default to current time if not set
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &MockTransparencyLog{
		UploadLogEntryFunc: func(_ context.Context, _ string, _ []byte, _ []byte, _ dsse.SignerVerifier) (*DockerTLExtension, error) {
			entry := new(models.LogEntryAnon)
			err := json.Unmarshal([]byte(TestEntry), entry)
			if err != nil {
				return nil, fmt.Errorf("error failed to unmarshal TestEntry: %w", err)
			}
			integratedTime := cfg.IntegratedTime.Unix()
			entry.IntegratedTime = &integratedTime
			entryBytes, err := json.Marshal(entry)
			if err != nil {
				return nil, fmt.Errorf("error failed to marshal TL entry: %w", err)
			}
			return &DockerTLExtension{
				Kind: "Mock",
				Data: json.RawMessage(entryBytes),
			}, nil
		},
		VerifyLogEntryFunc: func(_ context.Context, ext *DockerTLExtension, _, _ []byte) (time.Time, error) {
			// return the integrated time in the log entry without any checking
			entry := new(models.LogEntryAnon)
			entryBytes, err := json.Marshal(ext.Data)
			if err != nil {
				return time.Time{}, fmt.Errorf("error failed to marshal TL entry: %w", err)
			}
			err = entry.UnmarshalBinary(entryBytes)
			if err != nil {
				return time.Time{}, fmt.Errorf("error failed to unmarshal TL entry: %w", err)
			}
			if entry.IntegratedTime == nil {
				return time.Time{}, fmt.Errorf("error missing integrated time in TL entry")
			}
			return time.Unix(*entry.IntegratedTime, 0), nil
		},
	}
}

type MockTransparencyLog struct {
	UploadLogEntryFunc func(ctx context.Context, subject string, payload, signature []byte, signer dsse.SignerVerifier) (*DockerTLExtension, error)
	VerifyLogEntryFunc func(ctx context.Context, ext *DockerTLExtension, payload, publicKey []byte) (time.Time, error)
}

func (tl *MockTransparencyLog) UploadEntry(ctx context.Context, subject string, payload, signature []byte, signer dsse.SignerVerifier) (*DockerTLExtension, error) {
	if tl.UploadLogEntryFunc != nil {
		return tl.UploadLogEntryFunc(ctx, subject, payload, signature, signer)
	}
	return nil, nil
}

func (tl *MockTransparencyLog) VerifyEntry(ctx context.Context, ext *DockerTLExtension, payload, publicKey []byte) (time.Time, error) {
	if tl.VerifyLogEntryFunc != nil {
		return tl.VerifyLogEntryFunc(ctx, ext, payload, publicKey)
	}
	return time.Time{}, nil
}
