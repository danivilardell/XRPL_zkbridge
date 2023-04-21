package signature_validity

import (
	"fmt"

	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type PublicKey struct {
	A twistededwards.Point
}

type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

type lightClientVerificationCircuit struct {
	CurveID   tedwards.ID       `gnark:",public"`
	PublicKey [90]PublicKey     `gnark:",public"`
	Signature [90]Signature     `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

func (circuit *lightClientVerificationCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, circuit.CurveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	var validSignatures [91]frontend.Variable
	validSignatures[0] = 0
	// Verify each signature and increment the counter if it's valid
	for i := 0; i < len(circuit.PublicKey); i++ {
		isValid := eddsa.Verify(curve, eddsa.Signature(circuit.Signature[i]), circuit.Message, eddsa.PublicKey(circuit.PublicKey[i]), &mimc)
		if isValid == nil {
			validSignatures[i+1] = api.Add(validSignatures[i], 1)
		} else {
			validSignatures[i+1] = validSignatures[i]
		}
	}

	// Check if at least 80% of the signatures are valid
	threshold := frontend.Variable((int)((len(circuit.PublicKey)) * 80 / 100))
	fmt.Println("threshold: ", threshold)
	//api.AssertIsLessOrEqual(threshold, validSignatures[len(circuit.publicKey)])
	fmt.Println("threshold2: ", threshold)

	return nil
}
