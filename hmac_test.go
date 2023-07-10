package hmac_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/go-utils/hmac"
)

func Test_verifier_Do(t *testing.T) {
	t.Parallel()
	secretKey := "this-is-sample"
	mac := "66978174f0794c9a340a0b6ed3de35edf8d2b327a075d4bf576f6227d7b518a0"
	id := "dab46a91-e732-4be3-acad-3ddb35295ff4"
	timestamp := int64(1681327706)
	type args struct {
		message string
		mac     string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "正常",
			args: args{
				message: fmt.Sprintf("%s%d%d", id, 100, timestamp),
				mac:     mac,
			},
		},
		{
			name: "改竄済",
			args: args{
				message: fmt.Sprintf("%s%d%d", id, 999, timestamp),
				mac:     mac,
			},
			wantErr: true,
		},
		{
			name: "改竄済",
			args: args{
				message: fmt.Sprintf("%s%d%d", "56617d18-cb1e-47ea-8d8b-e7300df89c91", 100, timestamp),
				mac:     mac,
			},
			wantErr: true,
		},
		{
			name: "改竄済",
			args: args{
				message: fmt.Sprintf("%s%d%d", id, 100, 1681327707),
				mac:     mac,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			verifier := hmac.NewVerifier([]byte(secretKey))
			decodedMac, err := hex.DecodeString(tt.args.mac)
			if err != nil {
				t.Fatalf("failed to hex decode mac: %v", err)
			}
			if err = verifier.Do([]byte(tt.args.message), decodedMac); (err != nil) != tt.wantErr {
				t.Errorf("Do() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
