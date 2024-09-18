package attestation

import (
	"context"
	"reflect"
	"testing"

	"github.com/docker/attest/tlog"
	"github.com/docker/attest/tuf"
	"github.com/stretchr/testify/require"
)

func Test_verifier_GetLogVerifier(t *testing.T) {
	type fields struct {
		tufDownloader            tuf.Downloader
		signatureVerifierFactory SignatureVerifierFactory
		logVerifierFactory       LogVerifierFactory
	}
	type args struct {
		ctx  context.Context
		opts *VerifyOptions
	}
	rekor, err := tlog.NewRekorLog()
	require.NoError(t, err)
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    tlog.TransparencyLog
		wantErr bool
	}{
		{name: "skip_tl true", fields: fields{}, args: args{ctx: context.Background(), opts: &VerifyOptions{SkipTL: true}}},
		{name: "skip_tl false", fields: fields{}, args: args{ctx: context.Background(), opts: &VerifyOptions{SkipTL: false}}, want: rekor},
		{name: "tl: rekor", fields: fields{logVerifierFactory: func(_ context.Context, _ *VerifyOptions) (tlog.TransparencyLog, error) {
			return &tlog.Rekor{}, nil
		}}, args: args{ctx: context.Background(), opts: &VerifyOptions{}}, want: &tlog.Rekor{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &verifier{
				tufDownloader:            tt.fields.tufDownloader,
				signatureVerifierFactory: tt.fields.signatureVerifierFactory,
				logVerifierFactory:       tt.fields.logVerifierFactory,
			}
			got, err := v.GetLogVerifier(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("verifier.GetLogVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("verifier.GetLogVerifier() = %v, want %v", got, tt.want)
			}
		})
	}
}
