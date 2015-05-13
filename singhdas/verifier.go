package singhdas

import (
	"github.com/ronperry/cryptoedge/eccutil"
)

// Verify verifies that a signature signs message by the signer defined in SignerClient
func (client SignerClient) Verify(message []byte, signature *SignatureInt) (bool, error) {
	Hm := client.curve.GenHash(message)
	if Hm.Cmp(signature.Hm) != 0 {
		return false, eccutil.ErrHashDif
	}
	SG := client.curve.ScalarBaseMult(signature.S.Bytes())
	r2B := client.curve.ScalarMult(client.pubkey, signature.r2.Bytes())
	HmR := client.curve.ScalarMult(signature.R, Hm.Bytes())
	R2BHmR := client.curve.AddPoints(r2B, HmR)
	if SG.X.Cmp(R2BHmR.X) != 0 || SG.Y.Cmp(R2BHmR.Y) != 0 {
		return false, eccutil.ErrSigWrong
	}
	return true, nil
}
