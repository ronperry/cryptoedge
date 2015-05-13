package singhdas

import (
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ronperry/cryptoedge/eccutil"
	"github.com/ronperry/cryptoedge/genericblinding"
	"testing"
)

func GetParams(blindingServer genericblinding.BlindingServer) (genericblinding.BlindingParamClient, genericblinding.BlindingParamServer, error) {
	bpc, bps, err := blindingServer.GetParams()
	return bpc.(BlindingParamClient), bps.(BlindingParamServer), err
	//return blindingServer.GetParams()
}

func Test_Interface(t *testing.T) {
	c := eccutil.SetCurve(elliptic.P256, rand.Reader, eccutil.Sha1Hash)
	privkey, pubkey, err := c.GenerateKey()
	if err != nil {
		t.Fatalf("Error creating keys: %s", err)
	}
	signer := NewGenericBlindingServer(privkey, pubkey, c)
	clientParams, serverParams, err := GetParams(signer)
	if err != nil {
		t.Fatalf("Error GetParams: %s", err)
	}
	_, _ = clientParams, serverParams
}

// // does not implement wrong type for method
