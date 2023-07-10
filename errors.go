package hmac

import "golang.org/x/xerrors"

// NotEqual - MAC is not equal
var NotEqual = xerrors.New("mac is not equal")
