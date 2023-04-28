package signature_validity

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark"
	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/test"
)

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, tedwards.BN254},
	}

	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed)) //#nosec G404 -- This is a false positive

	for _, conf := range confs {

		snarkField, err := twistededwards.GetSnarkField(conf.curve)
		assert.NoError(err)
		snarkCurve := FieldToCurve(snarkField)

		// generate parameters for the signatures
		privKey, err := eddsa.New(conf.curve, randomness)
		assert.NoError(err, "generating eddsa key pair")

		// pick a message to sign
		var msg big.Int
		msg.Rand(randomness, snarkField)
		t.Log("msg to sign", msg.String())
		msgDataUnpadded := msg.Bytes()
		msgData := make([]byte, len(snarkField.Bytes()))
		copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)
		fmt.Println("message generated")

		// generate signature
		signature, err := privKey.Sign(msgData, conf.hash.New())
		assert.NoError(err, "signing message")
		fmt.Println("signature generated")

		// check if there is no problem in the signature
		pubKey := privKey.Public()
		checkSig, err := pubKey.Verify(signature, msgData, conf.hash.New())
		assert.NoError(err, "verifying signature")
		assert.True(checkSig, "signature verification failed")

		// pick a incorrect message to sign as a faliure test
		var msgIncorrect big.Int
		msgIncorrect.Rand(randomness, snarkField)
		t.Log("msg to sign", msgIncorrect.String())
		msgDataUnpaddedIncorrect := msgIncorrect.Bytes()
		msgDataIncorrect := make([]byte, len(snarkField.Bytes()))
		copy(msgDataIncorrect[len(msgDataIncorrect)-len(msgDataUnpaddedIncorrect):], msgDataUnpaddedIncorrect)
		fmt.Println("failure message generated")

		// generate signature
		signatureIncorrect, err := privKey.Sign(msgDataIncorrect, conf.hash.New())
		assert.NoError(err, "signing message")
		fmt.Println("failure signature generated")

		// check if there is no problem in the signature
		pubKeyIncorrect := privKey.Public()
		checkSigIncorrect, err := pubKey.Verify(signatureIncorrect, msgDataIncorrect, conf.hash.New())
		assert.NoError(err, "verifying signature")
		assert.True(checkSigIncorrect, "signature verification failed")

		// create and compile the circuit for signature verification
		var circuit lightClientVerificationCircuit
		circuit.curveID = conf.curve

		// verification with the correct Message
		{
			var witness lightClientVerificationCircuit
			witness.Message = msg
			for j := 0; j < 90; j++ {
				witness.PublicKey[j].Assign(conf.curve, pubKey.Bytes())
				witness.Signature[j].Assign(conf.curve, signature)
			}
			witness.One = 1
			witness.Zero = 0

			fmt.Println("witness generated")
			assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve), test.WithBackends(backend.GROTH16))
		}

		// verification with the 30% Message
		{
			var witness lightClientVerificationCircuit
			witness.Message = msg
			for j := 0; j < 63; j++ {
				witness.PublicKey[j].Assign(conf.curve, pubKey.Bytes())
				witness.Signature[j].Assign(conf.curve, signature)
			}
			for j := 63; j < 90; j++ {
				witness.PublicKey[j].Assign(conf.curve, pubKeyIncorrect.Bytes())
				witness.Signature[j].Assign(conf.curve, signatureIncorrect)
			}
			witness.One = 1
			witness.Zero = 0

			fmt.Println("failure witness generated")
			assert.SolvingFailed(&circuit, &witness, test.WithCurves(snarkCurve), test.WithBackends(backend.GROTH16))
		}
	}
}

func TestGenerateProofTime(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	conf := testData{hash.MIMC_BN254, tedwards.BN254}

	seed := time.Now().Unix()
	t.Logf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed)) //#nosec G404 -- This is a false positive

	snarkField, err := twistededwards.GetSnarkField(conf.curve)
	assert.NoError(err)
	//snarkCurve := FieldToCurve(snarkField)

	// generate parameters for the signatures
	privKey, err := eddsa.New(conf.curve, randomness)
	assert.NoError(err, "generating eddsa key pair")

	// pick a message to sign
	var msg big.Int
	msg.Rand(randomness, snarkField)
	t.Log("msg to sign", msg.String())
	msgDataUnpadded := msg.Bytes()
	msgData := make([]byte, len(snarkField.Bytes()))
	copy(msgData[len(msgData)-len(msgDataUnpadded):], msgDataUnpadded)
	fmt.Println("Message generated")

	// generate signature
	signature, err := privKey.Sign(msgData, conf.hash.New())
	assert.NoError(err, "signing message")
	fmt.Println("Signature generated")

	// check if there is no problem in the signature
	pubKey := privKey.Public()
	checkSig, err := pubKey.Verify(signature, msgData, conf.hash.New())
	assert.NoError(err, "verifying signature")
	assert.True(checkSig, "signature verification failed")

	assignment := &lightClientVerificationCircuit{
		curveID: conf.curve,
		Zero:    0,
		One:     1,
		Message: msg,
	}

	for i := 0; i < 90; i++ {
		assignment.PublicKey[i].Assign(conf.curve, pubKey.Bytes())
		assignment.Signature[i].Assign(conf.curve, signature)
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(err, "Error during witness generation")
	fmt.Println("Witness generated")

	start := time.Now()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, assignment)
	assert.NoError(err, "Error during compilation")
	fmt.Println("Circuit compiled in ", time.Since(start))

	start = time.Now()
	pk, vk, err := groth16.Setup(cs)
	assert.NoError(err, "Error during setup")
	fmt.Println("Setup done in ", time.Since(start))

	start = time.Now()
	proof, err := groth16.Prove(cs, pk, witness)
	assert.NoError(err, "Error during proof generation")
	fmt.Println("Proof generated in ", time.Since(start))

	start = time.Now()
	err = groth16.Verify(proof, vk, witness)
	assert.NoError(err, "Error during proof verification")
	fmt.Println("Proof verified in ", time.Since(start))

}

func FieldToCurve(q *big.Int) ecc.ID {
	var curves = make(map[string]ecc.ID)
	for _, c := range gnark.Curves() {
		fHex := c.ScalarField().Text(16)
		curves[fHex] = c
	}
	fHex := q.Text(16)
	curve, ok := curves[fHex]
	if !ok {
		return ecc.UNKNOWN
	}
	return curve
}
