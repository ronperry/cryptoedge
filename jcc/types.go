package jcc

import (
	"crypto/sha256"
	"github.com/ronperry/cryptoedge/eccutil"
	"github.com/ronperry/cryptoedge/genericblinding"
	"encoding/asn1"
)

// SchemeName is the name of this blinding scheme
const SchemeName = "JCC"

// BlindingParamClient is not needed in JCC
type BlindingParamClient struct {
	SchemeName string
	DataType   genericblinding.DataType
	PubKey     eccutil.Point
}

// NewBlindingParamClient returns a new BlindingParamClient
func NewBlindingParamClient(PubKey *eccutil.Point) BlindingParamClient {
	n := new(BlindingParamClient)
	n.SchemeName = SchemeName
	n.DataType = genericblinding.TypeBlindingParamClient
	n.PubKey = *PubKey
	return *n
}

// SchemeData returns general data for the scheme and BlindingData type
func (blindingParamClient BlindingParamClient) SchemeData() (string, genericblinding.DataType, *eccutil.Point) {
	return blindingParamClient.SchemeName, blindingParamClient.DataType, &blindingParamClient.PubKey
}

// Marshal a BlindingParamClient
func (blindingParamClient BlindingParamClient) Marshal() ([]byte, error) {
	return asn1.Marshal(blindingParamClient)
}

// Unmarshal []byte into BlindingParamClient
func (blindingParamClient BlindingParamClient) Unmarshal(b []byte) (genericblinding.BlindingData, error) {
	n := new(BlindingParamClient)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	if n.SchemeName != blindingParamClient.SchemeName {
		return nil, genericblinding.ErrBadScheme
	}
	if n.DataType != blindingParamClient.DataType {
		return nil, genericblinding.ErrBadType
	}
	if !eccutil.PointEqual(&blindingParamClient.PubKey, &n.PubKey) {
		return nil, genericblinding.ErrBadSigner
	}
	return n, nil
}

// UniqueID returns a unique ID for this element. Constant in this case (zeros)
func (blindingParamClient BlindingParamClient) UniqueID() []byte {
	return make([]byte, 0)
}

// --------------------------------
//
// --------------------------------

// ClearMessage contains a message
type ClearMessage struct {
	SchemeName string
	DataType   genericblinding.DataType
	Message    []byte
}

// NewClearMessage returns a new BlindingParamClient
func NewClearMessage(msg []byte) ClearMessage {
	n := new(ClearMessage)
	n.SchemeName = SchemeName
	n.DataType = genericblinding.TypeClearMessage
	n.Message = msg
	return *n
}

// SchemeData returns general data for the scheme and BlindingData type
func (clearMessage ClearMessage) SchemeData() (string, genericblinding.DataType, *eccutil.Point) {
	return clearMessage.SchemeName, clearMessage.DataType, nil
}

// Marshal a BlindingParamClient
func (clearMessage ClearMessage) Marshal() ([]byte, error) {
	return asn1.Marshal(clearMessage)
}

// Unmarshal []byte into BlindingParamClient
func (clearMessage ClearMessage) Unmarshal(b []byte) (genericblinding.BlindingData, error) {
	n := new(ClearMessage)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	if n.SchemeName != clearMessage.SchemeName {
		return nil, genericblinding.ErrBadScheme
	}
	if n.DataType != clearMessage.DataType {
		return nil, genericblinding.ErrBadType
	}
	return n, nil
}

// UniqueID returns a unique ID for this element. Constant in this case (zeros)
func (clearMessage ClearMessage) UniqueID() []byte {
	x := sha256.Sum256(clearMessage.Message)
	return x[:]
}

// --------------------------------
//
// --------------------------------

// BlindingFactors contains the client-produced blinding factors
type BlindingFactors struct {
	SchemeName string
	DataType   genericblinding.DataType
	PubKey     eccutil.Point
	Factor     []byte
}

// NewBlindingFactors returns a new BlindingParamClient
func NewBlindingFactors(PubKey *eccutil.Point) BlindingFactors {
	n := new(BlindingFactors)
	n.SchemeName = SchemeName
	n.DataType = genericblinding.TypeBlindingFactors
	n.PubKey = *PubKey
	return *n
}

// SchemeData returns general data for the scheme and BlindingData type
func (blindingFactors BlindingFactors) SchemeData() (string, genericblinding.DataType, *eccutil.Point) {
	return blindingFactors.SchemeName, blindingFactors.DataType, &blindingFactors.PubKey
}

// Marshal a BlindingParamClient
func (blindingFactors BlindingFactors) Marshal() ([]byte, error) {
	return asn1.Marshal(blindingFactors)
}

// Unmarshal []byte into BlindingParamClient
func (blindingFactors BlindingFactors) Unmarshal(b []byte) (genericblinding.BlindingData, error) {
	n := new(BlindingFactors)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	if n.SchemeName != blindingFactors.SchemeName {
		return nil, genericblinding.ErrBadScheme
	}
	if n.DataType != blindingFactors.DataType {
		return nil, genericblinding.ErrBadType
	}
	if !eccutil.PointEqual(&blindingFactors.PubKey, &n.PubKey) {
		return nil, genericblinding.ErrBadSigner
	}
	return n, nil
}

// UniqueID returns a unique ID for this element. Constant in this case (zeros)
func (blindingFactors BlindingFactors) UniqueID() []byte {
	x := sha256.Sum256(blindingFactors.Factor)
	return x[:]
}

// --------------------------------
//
// --------------------------------

// BlindMessage contains the client-produced blinding factors
type BlindMessage struct {
	SchemeName string
	DataType   genericblinding.DataType
	PubKey     eccutil.Point
	Message    eccutil.Point
}

// NewBlindMessage returns a new BlindingParamClient
func NewBlindMessage(PubKey *eccutil.Point) BlindMessage {
	n := new(BlindMessage)
	n.SchemeName = SchemeName
	n.DataType = genericblinding.TypeBlindMessage
	n.PubKey = *PubKey
	return *n
}

// SchemeData returns general data for the scheme and BlindingData type
func (blindMessage BlindMessage) SchemeData() (string, genericblinding.DataType, *eccutil.Point) {
	return blindMessage.SchemeName, blindMessage.DataType, &blindMessage.PubKey
}

// Marshal a BlindingParamClient
func (blindMessage BlindMessage) Marshal() ([]byte, error) {
	return asn1.Marshal(blindMessage)
}

// Unmarshal []byte into BlindingParamClient
func (blindMessage BlindMessage) Unmarshal(b []byte) (genericblinding.BlindingData, error) {
	n := new(BlindMessage)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	if n.SchemeName != blindMessage.SchemeName {
		return nil, genericblinding.ErrBadScheme
	}
	if n.DataType != blindMessage.DataType {
		return nil, genericblinding.ErrBadType
	}
	if !eccutil.PointEqual(&blindMessage.PubKey, &n.PubKey) {
		return nil, genericblinding.ErrBadSigner
	}
	return n, nil
}

// UniqueID returns a unique ID for this element. Constant in this case (zeros)
func (blindMessage BlindMessage) UniqueID() []byte {
	d := make([]byte, 64)
	d = append(d, blindMessage.Message.X.Bytes()...)
	d = append(d, blindMessage.Message.Y.Bytes()...)
	x := sha256.Sum256(d)
	return x[:]
}

// --------------------------------
//
// --------------------------------

// BlindSignature contains the client-produced blinding factors
type BlindSignature struct {
	SchemeName string
	DataType   genericblinding.DataType
	PubKey     eccutil.Point
	R, S       eccutil.Point
}

// NewBlindSignature returns a new BlindingParamClient
func NewBlindSignature(PubKey *eccutil.Point) BlindSignature {
	n := new(BlindSignature)
	n.SchemeName = SchemeName
	n.DataType = genericblinding.TypeBlindSignature
	n.PubKey = *PubKey
	return *n
}

// SchemeData returns general data for the scheme and BlindingData type
func (blindSignature BlindSignature) SchemeData() (string, genericblinding.DataType, *eccutil.Point) {
	return blindSignature.SchemeName, blindSignature.DataType, &blindSignature.PubKey
}

// Marshal a BlindingParamClient
func (blindSignature BlindSignature) Marshal() ([]byte, error) {
	return asn1.Marshal(blindSignature)
}

// Unmarshal []byte into BlindingParamClient
func (blindSignature BlindSignature) Unmarshal(b []byte) (genericblinding.BlindingData, error) {
	n := new(BlindSignature)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	if n.SchemeName != blindSignature.SchemeName {
		return nil, genericblinding.ErrBadScheme
	}
	if n.DataType != blindSignature.DataType {
		return nil, genericblinding.ErrBadType
	}
	if !eccutil.PointEqual(&blindSignature.PubKey, &n.PubKey) {
		return nil, genericblinding.ErrBadSigner
	}
	return n, nil
}

// UniqueID returns a unique ID for this element. Constant in this case (zeros)
func (blindSignature BlindSignature) UniqueID() []byte {
	d := make([]byte, 128)
	d = append(d, blindSignature.R.X.Bytes()...)
	d = append(d, blindSignature.R.Y.Bytes()...)
	d = append(d, blindSignature.S.X.Bytes()...)
	d = append(d, blindSignature.S.Y.Bytes()...)
	x := sha256.Sum256(d)
	return x[:]
}

// --------------------------------
//
// --------------------------------

// ClearSignature contains the client-produced blinding factors
type ClearSignature struct {
	SchemeName string
	DataType   genericblinding.DataType
	PubKey     eccutil.Point
	SB, R      eccutil.Point
}

// NewClearSignature returns a new BlindingParamClient
func NewClearSignature(PubKey *eccutil.Point) ClearSignature {
	n := new(ClearSignature)
	n.SchemeName = SchemeName
	n.DataType = genericblinding.TypeClearSignature
	n.PubKey = *PubKey
	return *n
}

// SchemeData returns general data for the scheme and BlindingData type
func (clearSignature ClearSignature) SchemeData() (string, genericblinding.DataType, *eccutil.Point) {
	return clearSignature.SchemeName, clearSignature.DataType, &clearSignature.PubKey
}

// Marshal a BlindingParamClient
func (clearSignature ClearSignature) Marshal() ([]byte, error) {
	return asn1.Marshal(clearSignature)
}

// Unmarshal []byte into BlindingParamClient
func (clearSignature ClearSignature) Unmarshal(b []byte) (genericblinding.BlindingData, error) {
	n := new(ClearSignature)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	if n.SchemeName != clearSignature.SchemeName {
		return nil, genericblinding.ErrBadScheme
	}
	if n.DataType != clearSignature.DataType {
		return nil, genericblinding.ErrBadType
	}
	if !eccutil.PointEqual(&clearSignature.PubKey, &n.PubKey) {
		return nil, genericblinding.ErrBadSigner
	}
	return n, nil
}

// UniqueID returns a unique ID for this element. Constant in this case (zeros)
func (clearSignature ClearSignature) UniqueID() []byte {
	d := make([]byte, 128)
	d = append(d, clearSignature.SB.X.Bytes()...)
	d = append(d, clearSignature.SB.Y.Bytes()...)
	d = append(d, clearSignature.R.X.Bytes()...)
	d = append(d, clearSignature.R.Y.Bytes()...)
	x := sha256.Sum256(d)
	return x[:]
}

// ------------------------------------------
//
// ------------------------------------------

// BlindingParamServer is not needed in JCC
type BlindingParamServer struct {
	SchemeName string
	DataType   genericblinding.DataType
	PubKey     eccutil.Point
}

// NewBlindingParamServer returns a new BlindingParamServer
func NewBlindingParamServer(PubKey *eccutil.Point) BlindingParamServer {
	n := new(BlindingParamServer)
	n.SchemeName = SchemeName
	n.DataType = genericblinding.TypeBlindingParamServer
	n.PubKey = *PubKey
	return *n
}

// SchemeData returns general data for the scheme and BlindingData type
func (blindingParamServer BlindingParamServer) SchemeData() (string, genericblinding.DataType, *eccutil.Point) {
	return blindingParamServer.SchemeName, blindingParamServer.DataType, &blindingParamServer.PubKey
}

// Marshal a BlindingParamServer
func (blindingParamServer BlindingParamServer) Marshal() ([]byte, error) {
	return asn1.Marshal(blindingParamServer)
}

// Unmarshal []byte into BlindingParamServer
func (blindingParamServer BlindingParamServer) Unmarshal(b []byte) (genericblinding.BlindingData, error) {
	n := new(BlindingParamServer)
	_, err := asn1.Unmarshal(b, n)
	if err != nil {
		return nil, err
	}
	if n.SchemeName != blindingParamServer.SchemeName {
		return nil, genericblinding.ErrBadScheme
	}
	if n.DataType != blindingParamServer.DataType {
		return nil, genericblinding.ErrBadType
	}
	if !eccutil.PointEqual(&blindingParamServer.PubKey, &n.PubKey) {
		return nil, genericblinding.ErrBadSigner
	}
	return n, nil
}

// UniqueID returns a unique ID for this element. Constant in this case (zeros)
func (blindingParamServer BlindingParamServer) UniqueID() []byte {
	return make([]byte, 0)
}
