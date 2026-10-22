package collectortest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// BodyCodec turns bodies a recording could not otherwise hold, such as the
// protobuf messages of a gRPC API, into JSON and back. Set the same codec as
// RecordOptions.Codec and Suite.Codec.
//
// Record decodes each response body the codec takes and scrubs the JSON
// with the rules for a JSON body. The recording holds that JSON. The kit's
// runs encode it again, so the framing and lengths around a value scrubbing
// replaced stay right. A replay serves what the codec encodes from the
// JSON, so anything the codec drops when it decodes, such as fields its
// message types lack, is missing from the replay. The sensitivity check
// changes the JSON as it changes a JSON body, and RequestBody matches the
// JSON the codec decodes a request's body to.
//
// The kit passes each body that is not empty to the codec before it checks
// for text or CBOR. When a decode returns no JSON and no error, the kit
// handles the body as it would without a codec. op names the call's
// operation, and header holds the request's headers, or the response's
// headers that a recording keeps.
type BodyCodec interface {
	// DecodeRequest returns the JSON a request's body stands for.
	DecodeRequest(op string, header http.Header, body []byte) ([]byte, error)

	// DecodeResponse returns the JSON a response's body stands for.
	DecodeResponse(op string, header http.Header, body []byte) ([]byte, error)

	// EncodeResponse returns the response body that JSON from
	// DecodeResponse stands for, after scrubbing or the sensitivity check
	// changed it.
	EncodeResponse(op string, header http.Header, json []byte) ([]byte, error)
}

// codecBody is the body_encoding of a body a BodyCodec decoded, which a
// recording holds as the codec's JSON.
const codecBody = "codec"

// decodeRequest returns the JSON codec decodes a request's body to, or nil
// when there is no codec, the body is empty, or the codec does not take it.
func decodeRequest(codec BodyCodec, op string, header http.Header, body []byte) ([]byte, error) {
	if codec == nil || len(body) == 0 {
		return nil, nil
	}
	return compactDecoded(codec.DecodeRequest(op, header, body))
}

// decodeResponse is decodeRequest for a response's body.
func decodeResponse(codec BodyCodec, op string, header http.Header, body []byte) ([]byte, error) {
	if codec == nil || len(body) == 0 {
		return nil, nil
	}
	return compactDecoded(codec.DecodeResponse(op, header, body))
}

// compactDecoded compacts the JSON a codec decoded a body to. No JSON means
// the codec does not take the body.
func compactDecoded(decoded []byte, err error) ([]byte, error) {
	switch {
	case err != nil:
		return nil, fmt.Errorf("the codec could not decode it: %w", err)
	case len(decoded) == 0:
		return nil, nil
	}
	var b bytes.Buffer
	if err := json.Compact(&b, decoded); err != nil {
		return nil, fmt.Errorf("the codec decoded it to something that is not JSON: %w", err)
	}
	return b.Bytes(), nil
}

// encodeResponse returns the body a response Record decoded with a codec
// stands for.
func encodeResponse(codec BodyCodec, r Response) (string, error) {
	if codec == nil {
		return "", errors.New("its body is JSON a BodyCodec decoded, which only a run with Suite.Codec set can encode")
	}
	body, err := codec.EncodeResponse(r.Operation, r.Header, []byte(r.Body))
	if err != nil {
		return "", fmt.Errorf("the codec could not encode its body: %w", err)
	}
	return string(body), nil
}

// decodedBody scrubs the JSON a codec decoded a body to, as it scrubs a JSON
// body, and fails when the result is no longer JSON.
func (s *scrubber) decodedBody(decoded []byte) (string, error) {
	out := s.text(string(decoded))
	if !json.Valid([]byte(out)) {
		return "", errors.New("scrubbing left the codec's JSON unreadable; check the ScrubRules replacements")
	}
	return out, nil
}

// mutateBody changes r's body for the sensitivity check, as mutateJSON or
// mutateCBOR changes it, and reports whether anything changed. A body Record
// decoded with a codec changes as JSON and stays decoded, and one
// Suite.Codec takes is decoded, changed, and encoded again. op is the
// operation whose calls r answered.
func (k *kit) mutateBody(op string, r Response) (string, bool, error) {
	if r.decoded {
		body, ok := mutateJSON(r.Body)
		return body, ok, nil
	}
	decoded, err := decodeResponse(k.suite.Codec, op, r.Header, []byte(r.Body))
	switch {
	case err != nil:
		return "", false, err
	case decoded != nil:
		body, ok := mutateJSON(string(decoded))
		if !ok {
			return r.Body, false, nil
		}
		encoded, err := k.suite.Codec.EncodeResponse(op, r.Header, []byte(body))
		if err != nil {
			return "", false, fmt.Errorf("the codec could not encode it once changed: %w", err)
		}
		return string(encoded), true, nil
	case isCBOR(r.Header.Get("Content-Type")):
		body, ok := mutateCBOR(r.Body)
		return body, ok, nil
	}
	body, ok := mutateJSON(r.Body)
	return body, ok, nil
}
