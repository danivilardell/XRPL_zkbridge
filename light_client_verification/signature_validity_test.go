package signature_validity

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/test"
)

func TestSignatureValidity(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit lightClientVerificationCircuit

	mimc := mimc.NewMiMC()

	var message fr.Element
	message.SetRandom()

	circuit.CurveID = tedwards.BN254
	circuit.Message = message

	for i := 0; i < 90; i++ {
		var r = io.Reader(strings.NewReader("test"))
		key, err := eddsa.GenerateKey(r)
		if err != nil {
			fmt.Println("err: ", err)
			t.Fatal(err)
		}
		signBytes, err := key.Sign(message.Marshal(), mimc)
		if err != nil {
			t.Fatal(err)
		}

		circuit.PublicKey[i].A.X = key.PublicKey.A.X.String()
		circuit.PublicKey[i].A.Y = key.PublicKey.A.Y.String()
		circuit.Signature[i].S = binary.BigEndian.Uint64(signBytes)
		circuit.Signature[i].R.X = key.PublicKey.A.X.String()
		circuit.Signature[i].R.Y = key.PublicKey.A.Y.String()
	}

	assert.ProverSucceeded(&circuit, &lightClientVerificationCircuit{
		CurveID:   circuit.CurveID,
		Message:   circuit.Message,
		Signature: circuit.Signature,
		PublicKey: circuit.PublicKey,
	})

}
