package edfsql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/lib-x/edf"
)

func init() {
	sql.Register("edfsql", &Driver{})
}

type Driver struct{}

type conn struct {
	db *edf.Database
}

type resultSet struct {
	columns []string
	dbTypes []string
	rows    [][]driver.Value
	index   int
}

type parsedQuery struct {
	table   string
	columns []string
	limit   int
	offset  int
}

var selectPattern = regexp.MustCompile(
	`(?is)^\s*select\s+(.+?)\s+from\s+("?[_a-zA-Z][_a-zA-Z0-9]*"?)` +
		`(?:\s+limit\s+(\d+))?(?:\s+offset\s+(\d+))?\s*;?\s*$`,
)

func (d *Driver) Open(name string) (driver.Conn, error) {
	db, err := edf.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open edfsql connection: %w", err)
	}
	return &conn{db: db}, nil
}

func (c *conn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("prepare is not supported")
}

func (c *conn) Close() error {
	return nil
}

func (c *conn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("transactions are not supported")
}

func (c *conn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if len(args) != 0 {
		return nil, fmt.Errorf("query arguments are not supported")
	}

	parsed, err := parseQuery(query)
	if err != nil {
		return nil, err
	}

	switch parsed.table {
	case "__tables":
		return buildTablesResult(c.db, parsed), nil
	case "__columns":
		return buildColumnsResult(c.db, parsed), nil
	case "__indexes":
		return buildIndexesResult(c.db, parsed), nil
	case "__layouts":
		return buildLayoutsResult(c.db, parsed), nil
	default:
		return buildTableResult(c.db, parsed)
	}
}

func (r *resultSet) Columns() []string {
	return slicesClone(r.columns)
}

func (r *resultSet) Next(dest []driver.Value) error {
	if r.index >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.index])
	r.index++
	return nil
}

func (r *resultSet) Close() error {
	return nil
}

func (r *resultSet) ColumnTypeDatabaseTypeName(index int) string {
	if index >= 0 && index < len(r.dbTypes) {
		return r.dbTypes[index]
	}
	return ""
}

func parseQuery(query string) (parsedQuery, error) {
	matches := selectPattern.FindStringSubmatch(query)
	if matches == nil {
		return parsedQuery{}, fmt.Errorf("unsupported query: %s", strings.TrimSpace(query))
	}

	columns := parseColumns(matches[1])
	if len(columns) == 0 {
		return parsedQuery{}, fmt.Errorf("no columns selected")
	}

	limit, err := parseOptionalInt(matches[3])
	if err != nil {
		return parsedQuery{}, err
	}
	offset, err := parseOptionalInt(matches[4])
	if err != nil {
		return parsedQuery{}, err
	}

	return parsedQuery{
		table:   strings.Trim(strings.ToLower(matches[2]), `"`),
		columns: columns,
		limit:   limit,
		offset:  offset,
	}, nil
}

func parseColumns(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "*" {
		return []string{"*"}
	}

	parts := strings.Split(raw, ",")
	columns := make([]string, 0, len(parts))
	for _, part := range parts {
		name := strings.Trim(strings.TrimSpace(part), `"`)
		if name != "" {
			columns = append(columns, name)
		}
	}
	return columns
}

func parseOptionalInt(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse integer %q: %w", raw, err)
	}
	return value, nil
}

func buildTablesResult(db *edf.Database, parsed parsedQuery) *resultSet {
	allColumns := []string{"name", "header_offset", "field_count", "index_count", "record_count", "queryable", "decodable"}
	columns, indexes := projectColumns(parsed.columns, allColumns)

	source := db.Tables()
	rows := make([][]driver.Value, 0, len(source))
	for _, table := range source {
		row := []driver.Value{
			table.Name,
			table.HeaderOffset,
			int64(len(table.Fields)),
			int64(len(table.Indexes)),
			int64(table.RecordCount),
			table.Queryable,
			table.Decodable,
		}
		rows = append(rows, projectRow(row, indexes))
	}

	return &resultSet{
		columns: columns,
		dbTypes: projectTypes([]string{"TEXT", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "BOOLEAN", "BOOLEAN"}, indexes),
		rows:    sliceRows(rows, parsed.limit, parsed.offset),
	}
}

func buildColumnsResult(db *edf.Database, parsed parsedQuery) *resultSet {
	allColumns := []string{"table_name", "ordinal", "name", "type_code", "raw_width", "slot_offset"}
	columns, indexes := projectColumns(parsed.columns, allColumns)

	rows := make([][]driver.Value, 0, 128)
	for _, table := range db.Tables() {
		for ordinal, field := range table.Fields {
			row := []driver.Value{
				table.Name,
				int64(ordinal),
				field.Name,
				int64(field.TypeCode),
				int64(field.RawWidth),
				int64(field.SlotOffset),
			}
			rows = append(rows, projectRow(row, indexes))
		}
	}

	return &resultSet{
		columns: columns,
		dbTypes: projectTypes([]string{"TEXT", "INTEGER", "TEXT", "INTEGER", "INTEGER", "INTEGER"}, indexes),
		rows:    sliceRows(rows, parsed.limit, parsed.offset),
	}
}

func buildIndexesResult(db *edf.Database, parsed parsedQuery) *resultSet {
	allColumns := []string{"table_name", "ordinal", "name"}
	columns, indexes := projectColumns(parsed.columns, allColumns)

	rows := make([][]driver.Value, 0, 64)
	for _, table := range db.Tables() {
		for ordinal, index := range table.Indexes {
			row := []driver.Value{
				table.Name,
				int64(ordinal),
				index.Name,
			}
			rows = append(rows, projectRow(row, indexes))
		}
	}

	return &resultSet{
		columns: columns,
		dbTypes: projectTypes([]string{"TEXT", "INTEGER", "TEXT"}, indexes),
		rows:    sliceRows(rows, parsed.limit, parsed.offset),
	}
}

func buildLayoutsResult(db *edf.Database, parsed parsedQuery) *resultSet {
	allColumns := []string{
		"name",
		"record_count",
		"record_root",
		"page_root",
		"stride",
		"bitmap_size",
		"field_count",
		"queryable",
		"decodable",
	}
	columns, indexes := projectColumns(parsed.columns, allColumns)

	rows := make([][]driver.Value, 0, 64)
	for _, table := range db.Tables() {
		var (
			stride     int64
			bitmapSize int64
			fieldCount int64
		)
		if table.Layout != nil {
			stride = int64(table.Layout.Stride)
			bitmapSize = int64(table.Layout.BitmapSize)
			fieldCount = int64(table.Layout.FieldCount)
		}
		row := []driver.Value{
			table.Name,
			int64(table.RecordCount),
			table.RecordRoot,
			table.PageRoot,
			stride,
			bitmapSize,
			fieldCount,
			table.Queryable,
			table.Decodable,
		}
		rows = append(rows, projectRow(row, indexes))
	}

	return &resultSet{
		columns: columns,
		dbTypes: projectTypes(
			[]string{"TEXT", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "INTEGER", "BOOLEAN", "BOOLEAN"},
			indexes,
		),
		rows: sliceRows(rows, parsed.limit, parsed.offset),
	}
}

func buildTableResult(db *edf.Database, parsed parsedQuery) (driver.Rows, error) {
	table, ok := db.Table(parsed.table)
	if !ok {
		return nil, fmt.Errorf("table %q not found", parsed.table)
	}
	if !table.Queryable {
		return nil, fmt.Errorf("table %q is not queryable yet", parsed.table)
	}

	allColumns := make([]string, 0, len(table.Fields))
	for _, field := range table.Fields {
		allColumns = append(allColumns, field.Name)
	}
	columns, indexes := projectColumns(parsed.columns, allColumns)

	rawRows, err := db.ReadRawRows(table.Name, parsed.limit, parsed.offset)
	if err != nil {
		return nil, err
	}

	rows := make([][]driver.Value, 0, len(rawRows))
	for _, raw := range rawRows {
		row := make([]driver.Value, 0, len(table.Fields))
		for idx, value := range raw.Values {
			if !table.Decodable {
				row = append(row, value)
				continue
			}
			decoded, err := db.DecodeValue(table.Name, table.Fields[idx].Name, value)
			if err != nil {
				row = append(row, value)
				continue
			}
			row = append(row, driverValue(decoded))
		}
		rows = append(rows, projectRow(row, indexes))
	}

	dbTypes := make([]string, 0, len(columns))
	for _, column := range columns {
		if !table.Decodable {
			dbTypes = append(dbTypes, "BLOB")
			continue
		}
		fieldType := "BLOB"
		for _, field := range table.Fields {
			if strings.EqualFold(field.Name, column) {
				switch field.TypeCode {
				case 0x0005:
					fieldType = "BOOLEAN"
				case 0x0003:
					fieldType = "INTEGER"
				case 0x0009, 0x000a, 0x000b:
					fieldType = "TEXT"
				case 0x2001, 0x2201, 0x4018, 0x8018:
					fieldType = "TEXT"
				case 0x000f, 0x0010, 0x0027:
					fieldType = "BLOB"
				default:
					fieldType = "BLOB"
				}
				break
			}
		}
		dbTypes = append(dbTypes, fieldType)
	}

	return &resultSet{
		columns: columns,
		dbTypes: dbTypes,
		rows:    rows,
	}, nil
}

func driverValue(decoded edf.DecodedValue) driver.Value {
	switch decoded.Kind {
	case edf.DecodedBool:
		return decoded.Bool
	case edf.DecodedInt32:
		return int64(decoded.Int32)
	case edf.DecodedDate, edf.DecodedTime, edf.DecodedDateTime:
		return decoded.String
	case edf.DecodedString:
		return decoded.String
	case edf.DecodedExternal:
		if decoded.String != "" {
			return decoded.String
		}
		if len(decoded.Bytes) > 0 {
			return decoded.Bytes
		}
		return decoded.Raw
	default:
		return decoded.Raw
	}
}

func projectColumns(selected, available []string) ([]string, []int) {
	if len(selected) == 1 && selected[0] == "*" {
		indexes := make([]int, 0, len(available))
		for idx := range available {
			indexes = append(indexes, idx)
		}
		return slicesClone(available), indexes
	}

	indexes := make([]int, 0, len(selected))
	columns := make([]string, 0, len(selected))
	for _, sel := range selected {
		for idx, name := range available {
			if strings.EqualFold(sel, name) {
				indexes = append(indexes, idx)
				columns = append(columns, name)
				break
			}
		}
	}
	return columns, indexes
}

func projectTypes(all []string, indexes []int) []string {
	out := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, all[idx])
	}
	return out
}

func projectRow(row []driver.Value, indexes []int) []driver.Value {
	out := make([]driver.Value, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, row[idx])
	}
	return out
}

func sliceRows(rows [][]driver.Value, limit, offset int) [][]driver.Value {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(rows) {
		return [][]driver.Value{}
	}
	end := len(rows)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return rows[offset:end]
}

func slicesClone[T any](values []T) []T {
	out := make([]T, len(values))
	copy(out, values)
	return out
}
