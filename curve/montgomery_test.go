package curve

import (
	"crypto/rand"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/curve/scalar"
	"github.com/oasisprotocol/curve25519-voi/internal/field"
)

func TestMontgomery(t *testing.T) {
	t.Run("EdwardsPointFromMontgomery", testMontgomeryEdwardsPointFromMontgomery)
	t.Run("EdwardsPointFromMontgomery/RejectsTwist", testMontgomeryEdwardsPointFromMontgomeryRejectsTwist)
	t.Run("FromEdwards", testMontgomeryFromEdwards)
	t.Run("Equal", testMontgomeryEqual)
	t.Run("Mul", testMontgomeryMul)
}

func testMontgomeryEdwardsPointFromMontgomery(t *testing.T) {
	var p EdwardsPoint
	if err := p.FromMontgomery(&X25519_BASEPOINT, 0); err != nil {
		t.Fatalf("FromMontgomery(X25519_BASEPOINT, 0)")
	}
	if p.Equal(&ED25519_BASEPOINT_POINT) != 1 {
		t.Fatalf("FromMontgomery(X25519_BASEPOINT, 0) != ED25519_BASEPOINT_POINT (Got: %v)", p)
	}

	negBasepoint := ED25519_BASEPOINT_POINT
	negBasepoint.Neg()
	if err := p.FromMontgomery(&X25519_BASEPOINT, 1); err != nil {
		t.Fatalf("FromMontgomery(X25519_BASEPOINT, 0)")
	}
	if p.Equal(&negBasepoint) != 1 {
		t.Fatalf("FromMontgomery-X25519_BASEPOINT, 1) != -ED25519_BASEPOINT_POINT (Got: %v)", p)
	}
}

func testMontgomeryEdwardsPointFromMontgomeryRejectsTwist(t *testing.T) {
	one, minusOne := field.One(), field.MinusOne()
	var two field.FieldElement
	two.Add(&one, &one)

	// u = 2 corresponds to a point on the twist.
	var pM MontgomeryPoint
	_ = two.ToBytes(pM[:])

	var p EdwardsPoint
	if err := p.FromMontgomery(&pM, 0); err == nil {
		t.Fatalf("FromMontgomery(2, 0) != error (Got: %v)", p)
	}

	// u = -1 corresponds to a point on the twist, but should be
	// checked explicitly because it's an exceptional point for the
	// birational map.  For instance, libsignal will accept it.
	_ = minusOne.ToBytes(pM[:])
	if err := p.FromMontgomery(&pM, 0); err == nil {
		t.Fatalf("FromMontgomery(-1, 0) != error (Got: %v)", p)
	}
}

func testMontgomeryFromEdwards(t *testing.T) {
	var p MontgomeryPoint
	p.FromEdwards(&ED25519_BASEPOINT_POINT)
	if p.Equal(&X25519_BASEPOINT) != 1 {
		t.Fatalf("FromEdwards(ED25519_BASEPOINT_POINT) != X25519_BASEPOINT (Got: %v)", p)
	}
}

func testMontgomeryEqual(t *testing.T) {
	u18Bytes := [MontgomeryPointSize]byte{18}
	u18UnreducedBytes := [MontgomeryPointSize]byte{
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	}

	u18, u18Unreduced := MontgomeryPoint(u18Bytes), MontgomeryPoint(u18UnreducedBytes)
	if u18.Equal(&u18Unreduced) != 1 {
		t.Fatalf("u18 != u18Unreduced")
	}
}

func testMontgomeryMul(t *testing.T) {
	var s scalar.Scalar
	if err := s.Random(rand.Reader); err != nil {
		t.Fatalf("s.Random(): %v", err)
	}

	pEdwards := ED25519_BASEPOINT_TABLE.Mul(&s)
	var pMontgomery MontgomeryPoint
	pMontgomery.FromEdwards(&pEdwards)

	var expected EdwardsPoint
	expected.Mul(&pEdwards, &s)

	var result MontgomeryPoint
	result.Mul(&pMontgomery, &s)

	var expectedMontgomery MontgomeryPoint
	expectedMontgomery.FromEdwards(&expected)
	if result.Equal(&expectedMontgomery) != 1 {
		t.Fatalf("s * p_edwards != s * p_montgomery (Got: %v, %v)", expectedMontgomery, result)
	}
}
