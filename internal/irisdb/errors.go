package irisdb

import "errors"

var (
	ErrNotEDF                  = errors.New("not an IrisDB/eDiary file")
	ErrShortRead               = errors.New("short read")
	ErrTableNotFound           = errors.New("table not found")
	ErrRecordLayoutUnavailable = errors.New("record layout unavailable")
	ErrUnsupportedFieldType    = errors.New("unsupported field type")
)
