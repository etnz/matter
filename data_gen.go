//go:build ignore

package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

// errors
// xml:  the Channel Cluster uses a Additional Info Struct but does not define it.
// spec: spec reference it's definition in another cluster.

// Config defines the generation rules and type mappings.
type generatorConfig struct {
	TypeMapping         map[string]string
	TypeAliases         map[string]string
	TypeNameExceptions  map[string]string
	EnumValueExceptions map[string]string
	KnownStructs        map[string]bool
}

var Config = generatorConfig{
	TypeMapping: map[string]string{
		"bool":            "bool",
		"boolean":         "bool",
		"map8":            "uint8",
		"map16":           "uint16",
		"map32":           "uint32",
		"map64":           "uint64",
		"uint8":           "uint8",
		"uint16":          "uint16",
		"uint24":          "uint32",
		"uint32":          "uint32",
		"uint40":          "uint64",
		"uint48":          "uint64",
		"uint56":          "uint64",
		"uint64":          "uint64",
		"int8":            "int8",
		"int16":           "int16",
		"int24":           "int32",
		"int32":           "int32",
		"int40":           "int64",
		"int48":           "int64",
		"int56":           "int64",
		"int64":           "int64",
		"float":           "float32",
		"single":          "float32",
		"double":          "float64",
		"octet_string":    "[]byte",
		"string":          "string",
		"char_string":     "string",
		"attrib_id":       "AttributeID",
		"attribute-id":    "AttributeID",
		"cluster-id":      "ClusterID",
		"command-id":      "CommandID",
		"endpoint-id":     "EndpointID",
		"endpoint-no":     "EndpointID",
		"event-id":        "EventID",
		"fabric-id":       "FabricID",
		"field-id":        "FieldID",
		"group-id":        "GroupID",
		"node-id":         "NodeID",
		"percent":         "Percent",
		"percent100ths":   "Percent100ths",
		"status":          "Status",
		"status-code":     "Status",
		"tag":             "Tag",
		"namespace":       "Namespace",
		"vendor-id":       "VendorID",
		"devicetype-id":   "DeviceTypeID",
		"power-mW":        "PowerMW",
		"power-mVA":       "PowerMVA",
		"money":           "Money",
		"epoch-us":        "EpochUS",
		"epoch-s":         "EpochS",
		"utc":             "UTC",
		"date":            "uint32",
		"tod":             "uint32",
		"TLSCAID":         "uint16",
		"WebRTCSessionID": "uint16",
		"VideoStreamID":   "uint16",
		"AudioStreamID":   "uint16",
		"subject-id":      "SubjectID",
		"devtype-id":      "DeviceTypeID",
		"octstr":          "[]byte",
		"elapsed-s":       "ElapsedS",
		"energy-mWh":      "EnergyMWh",
		"energy-mVAh":     "EnergyMVAh",
		"energy-mVARh":    "EnergyMVARh",
		"message-id":      "[]byte",
		"enum16":          "uint16",
		"fabric-idx":      "FabricIndex",
		"hwadr":           "[]byte",
		"ipv4adr":         "[]byte",
		"ipv6adr":         "[]byte",
		"systime-ms":      "SystemTimeMS",
		"temperature":     "Temperature",
		"action-id":       "ActionID",
		"entry-idx":       "EntryIndex",
		"event-no":        "EventNumber",
		"data-ver":        "DataVersion",
	},
	TypeAliases: map[string]string{
		"SubjectID":     "uint64",
		"NodeID":        "uint64",
		"FabricID":      "uint64",
		"EventNumber":   "uint64",
		"ClusterID":     "uint32",
		"AttributeID":   "uint32",
		"CommandID":     "uint32",
		"EventID":       "uint32",
		"DeviceTypeID":  "uint32",
		"DataVersion":   "uint32",
		"FieldID":       "uint32",
		"EndpointID":    "uint16",
		"GroupID":       "uint16",
		"VendorID":      "uint16",
		"EntryIndex":    "uint16",
		"FabricIndex":   "uint8",
		"ActionID":      "uint8",
		"Status":        "uint8",
		"Tag":           "uint8",
		"Namespace":     "uint8",
		"Percent":       "uint8",
		"Percent100ths": "uint16",
		"EpochUS":       "uint64",
		"EpochS":        "uint32",
		"UTC":           "uint32",
		"SystemTimeMS":  "uint64",
		"ElapsedS":      "uint32",
		"Temperature":   "int16",
		"PowerMW":       "int64",
		"PowerMVA":      "int64",
		"EnergyMWh":     "int64",
		"EnergyMVAh":    "int64",
		"EnergyMVARh":   "int64",
		"Money":         "int64",
	},
	TypeNameExceptions: map[string]string{
		// collisions: type names that collides with package names.
		"MessageStruct": "DMMessage",
		"ClientStruct":  "DMClient",
	},
	EnumValueExceptions: map[string]string{
		// enum: enum names that are invalid Go identifiers.
		// "AudioCodecAAC-LC":                           "AudioCodecAAC_LC",
		// "ModeTagConvection Bake":                     "ModeTagConvection_Bake",
		// "ModeTagConvection Roast":                    "ModeTagConvection_Roast",
		// "ModeTagAir Fry":                             "ModeTagAir_Fry",
		// "ModeTagAir Sous Vide":                       "ModeTagAir_Sous_Vide",
		// "ModeTagFrozen Food":                         "ModeTagFrozen_Food",
		// "ModeTagVacuum then Mop":                     "ModeTagVacuum_then_Mop",
		// "ProductIdentifierTypeGTIN-8":                "ProductIdentifierTypeGTIN_8",
		// "ProductIdentifierTypeGTIN-14":               "ProductIdentifierTypeGTIN_14",
		"SoftwareVersionCertificationStatusdev-test": "SoftwareVersionCertificationStatusdevtest",
	},
	KnownStructs: make(map[string]bool),
}

func (c *generatorConfig) RenameStruct(name string) string {
	if n, ok := c.TypeNameExceptions[name]; ok {
		return n
	}

	//

	if strings.HasSuffix(name, "Struct") {
		return name[:len(name)-6]
	}
	// if strings.HasSuffix(name, "Enum") {
	// 	return name[:len(name)-4]
	// }
	return name
}

func (c *generatorConfig) RenameField(name string) string {
	return name
}

func (c *generatorConfig) RenameCluster(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", ""), "/", "")
}

func (c *generatorConfig) RenameEnumValue(enumName, valueName string) string {
	key := enumName + valueName
	if n, ok := c.EnumValueExceptions[key]; ok {
		return strings.TrimPrefix(n, enumName)
	}
	return strings.ReplaceAll(strings.ReplaceAll(valueName, "-", "_"), " ", "_")
}

// --- XML Structures ---

type StructsRoot struct {
	XMLName xml.Name    `xml:"structs"`
	Structs []StructDef `xml:"struct"`
}

type EnumsRoot struct {
	XMLName xml.Name  `xml:"enums"`
	Enums   []EnumDef `xml:"enum"`
}

type ClusterRoot struct {
	XMLName   xml.Name   `xml:"cluster"`
	Name      string     `xml:"name,attr"`
	DataTypes *DataTypes `xml:"dataTypes"`
}

type DataTypes struct {
	Structs []StructDef `xml:"struct"`
	Enums   []EnumDef   `xml:"enum"`
	Bitmaps []BitmapDef `xml:"bitmap"`
	Numbers []NumberDef `xml:"number"`
}

type StructDef struct {
	Name    string     `xml:"name,attr"`
	Fields  []FieldDef `xml:"field"`
	Cluster string
}

type FieldDef struct {
	ID               int               `xml:"id,attr"`
	Name             string            `xml:"name,attr"`
	Type             string            `xml:"type,attr"`
	Entry            *EntryDef         `xml:"entry"`
	Quality          *QualityDef       `xml:"quality"`
	OptionalConform  *OptionalConform  `xml:"optionalConform"`
	MandatoryConform *MandatoryConform `xml:"mandatoryConform"`
	DeprecateConform *DeprecateConform `xml:"deprecateConform"`
}

type EntryDef struct {
	Type string `xml:"type,attr"`
}

type QualityDef struct {
	Nullable string `xml:"nullable,attr"`
}

type OptionalConform struct {
}

type MandatoryConform struct {
}

type DeprecateConform struct {
}

type EnumDef struct {
	Name    string     `xml:"name,attr"`
	Items   []EnumItem `xml:"item"`
	Cluster string
}

type EnumItem struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type BitmapDef struct {
	Name    string        `xml:"name,attr"`
	Items   []BitfieldDef `xml:"bitfield"`
	Cluster string
}

type BitfieldDef struct {
	Name string `xml:"name,attr"`
	Bit  int    `xml:"bit,attr"`
}

type NumberDef struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Cluster string
}

// --- Go Generation Structures ---

type GoStruct struct {
	Name   string
	Fields []GoField
}

type GoField struct {
	Name          string
	Type          string
	Tag           int
	IsPointer     bool
	IsList        bool
	IsStruct      bool
	BaseType      string
	PrimitiveType string
}

type GoEnum struct {
	Name     string
	BaseType string
	Items    []GoEnumItem
}

type GoEnumItem struct {
	Name  string
	Value string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: typegen <path_to_data_model_dir>")
		return
	}
	outputFile := "data.go"
	rootDir := os.Args[1]

	var rawStructs []StructDef
	var rawEnums []EnumDef
	var rawBitmaps []BitmapDef
	var rawNumbers []NumberDef

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(path) != ".xml" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		data, _ := io.ReadAll(f)

		var sRoot StructsRoot
		if xml.Unmarshal(data, &sRoot) == nil && len(sRoot.Structs) > 0 {
			for _, s := range sRoot.Structs {
				rawStructs = append(rawStructs, s)
			}
		}

		var eRoot EnumsRoot
		if xml.Unmarshal(data, &eRoot) == nil && len(eRoot.Enums) > 0 {
			for _, e := range eRoot.Enums {
				rawEnums = append(rawEnums, e)
			}
		}

		var cRoot ClusterRoot
		if xml.Unmarshal(data, &cRoot) == nil && cRoot.DataTypes != nil {
			for i := range cRoot.DataTypes.Structs {
				cRoot.DataTypes.Structs[i].Cluster = cRoot.Name
			}
			for i := range cRoot.DataTypes.Enums {
				cRoot.DataTypes.Enums[i].Cluster = cRoot.Name
			}
			for i := range cRoot.DataTypes.Bitmaps {
				cRoot.DataTypes.Bitmaps[i].Cluster = cRoot.Name
			}
			for i := range cRoot.DataTypes.Numbers {
				cRoot.DataTypes.Numbers[i].Cluster = cRoot.Name
			}
			rawStructs = append(rawStructs, cRoot.DataTypes.Structs...)
			rawEnums = append(rawEnums, cRoot.DataTypes.Enums...)
			rawBitmaps = append(rawBitmaps, cRoot.DataTypes.Bitmaps...)
			rawNumbers = append(rawNumbers, cRoot.DataTypes.Numbers...)
		}

		return nil
	})

	if err != nil {
		panic(err)
	}

	// Pre-register structs to handle forward references and cluster scoping
	for _, s := range rawStructs {
		name := s.Name
		if s.Cluster != "" {
			name = Config.RenameCluster(s.Cluster) + name
		}
		goName := Config.RenameStruct(name)
		Config.TypeMapping[s.Cluster+s.Name] = goName
		Config.KnownStructs[goName] = true
	}

	for _, n := range rawNumbers {
		name := n.Name
		if n.Cluster != "" {
			name = Config.RenameCluster(n.Cluster) + name
		}
		goName := Config.RenameStruct(name)
		baseType := n.Type
		if mapped, ok := Config.TypeMapping[n.Type]; ok {
			baseType = mapped
		}
		Config.TypeMapping[n.Cluster+n.Name] = goName
		Config.TypeAliases[goName] = baseType
	}

	var enums []GoEnum
	for _, e := range rawEnums {
		enums = append(enums, processEnum(e))
	}
	for _, b := range rawBitmaps {
		enums = append(enums, processBitmap(b))
	}

	var structs []GoStruct
	for _, s := range rawStructs {
		structs = append(structs, processStruct(s))
	}

	generateGoCode(outputFile, structs, enums)
}

func processEnum(e EnumDef) GoEnum {
	name := e.Name
	if e.Cluster != "" {
		name = Config.RenameCluster(e.Cluster) + name
	}
	ge := GoEnum{
		Name: Config.RenameStruct(name),
	}

	var maxVal int64
	for _, i := range e.Items {
		if i.Name == "ReservedForFutureUse" {
			continue
		}
		val, _ := strconv.ParseInt(i.Value, 0, 64)
		if val > maxVal {
			maxVal = val
		}
		ge.Items = append(ge.Items, GoEnumItem{
			Name:  Config.RenameEnumValue(ge.Name, i.Name),
			Value: i.Value,
		})
	}

	if maxVal <= 255 {
		ge.BaseType = "uint8"
	} else if maxVal <= 65535 {
		ge.BaseType = "uint16"
	} else {
		ge.BaseType = "uint32"
	}

	// Register the enum in the type mapping so structs can use it
	Config.TypeMapping[e.Cluster+e.Name] = ge.Name
	// Register the alias so it is treated as a primitive type (not a struct)
	Config.TypeAliases[ge.Name] = ge.BaseType

	return ge
}

func processBitmap(b BitmapDef) GoEnum {
	name := b.Name
	if b.Cluster != "" {
		name = Config.RenameCluster(b.Cluster) + name
	}
	ge := GoEnum{
		Name: Config.RenameStruct(name),
	}

	var maxBit int
	for _, i := range b.Items {
		if i.Bit > maxBit {
			maxBit = i.Bit
		}
		val := fmt.Sprintf("0x%X", uint64(1)<<i.Bit)
		ge.Items = append(ge.Items, GoEnumItem{
			Name:  Config.RenameEnumValue(ge.Name, i.Name),
			Value: val,
		})
	}

	if maxBit < 8 {
		ge.BaseType = "uint8"
	} else if maxBit < 16 {
		ge.BaseType = "uint16"
	} else if maxBit < 32 {
		ge.BaseType = "uint32"
	} else {
		ge.BaseType = "uint64"
	}

	Config.TypeMapping[b.Cluster+b.Name] = ge.Name
	Config.TypeAliases[ge.Name] = ge.BaseType

	return ge
}

func processStruct(s StructDef) GoStruct {
	name := s.Name
	if s.Cluster != "" {
		name = Config.RenameCluster(s.Cluster) + name
	}
	gs := GoStruct{
		Name: Config.RenameStruct(name),
	}

	for _, f := range s.Fields {
		if f.DeprecateConform != nil {
			continue
		}
		if f.Type == "" {
			fmt.Printf("cluster %s struct %s field %s has no type\n", s.Cluster, s.Name, f.Name)
		}

		gf := GoField{
			Name: Config.RenameField(f.Name),
			Tag:  f.ID,
		}

		xmlType := f.Type
		if f.Type == "list" && f.Entry != nil {
			xmlType = f.Entry.Type
			gf.IsList = true
		}

		goType, ok := Config.TypeMapping[s.Cluster+xmlType]
		if !ok {
			goType, ok = Config.TypeMapping[xmlType]
		}

		if !ok {
			goType = Config.RenameStruct(xmlType)
			gf.IsStruct = true
			gf.PrimitiveType = goType
		}
		gf.BaseType = goType

		if Config.KnownStructs[goType] {
			gf.IsStruct = true
		}

		if gf.IsList {
			gf.Type = "[]" + goType
		} else {
			gf.Type = goType
		}

		if !gf.IsStruct {
			if prim, ok := Config.TypeAliases[goType]; ok {
				gf.PrimitiveType = prim
			} else {
				gf.PrimitiveType = goType
			}
		}

		isNullable := f.Quality != nil && f.Quality.Nullable == "true"
		isOptional := f.OptionalConform != nil

		if isNullable || isOptional {
			gf.IsPointer = true
		}
		if gf.IsList {
			gf.IsPointer = false
		}

		gs.Fields = append(gs.Fields, gf)
	}
	return gs
}

type GenData struct {
	Aliases []AliasDef
	Structs []GoStruct
	Enums   []GoEnum
}

type AliasDef struct {
	Name string
	Base string
}

func generateGoCode(filename string, structs []GoStruct, enums []GoEnum) {
	tmpl := `// Code generated by data_gen.go. DO NOT EDIT.

package matter

import (
	"fmt"
	"io"

	"github.com/etnz/matter/tlv"
)

{{range .Aliases}}
type {{.Name}} {{.Base}}
{{end}}

{{range .Enums}}
type {{.Name}} {{.BaseType}}

const (
{{$enumName := .Name}}{{range .Items}}	{{$enumName}}{{.Name}} {{$enumName}} = {{.Value}}
{{end}})
{{end}}

{{range .Structs}}
type {{.Name}} struct {
{{range .Fields}}	{{.Name}} {{if .IsPointer}}*{{end}}{{.Type}} // Tag {{.Tag}}
{{end}}}

func (s *{{.Name}}) Encode() tlv.Struct {
	st := make(tlv.Struct)
{{range .Fields}}	// Field: {{.Name}} Tag: {{.Tag}}
    {{if .IsPointer}}if s.{{.Name}} != nil {
        {{if .IsStruct}}st[tlv.ContextTag({{.Tag}})] = s.{{.Name}}.Encode()
        {{else}}st[tlv.ContextTag({{.Tag}})] = {{CastToTarget .PrimitiveType}}(*s.{{.Name}}){{end}}
    }{{else}}{{if .IsList}}if len(s.{{.Name}}) > 0 {
        {{if .IsStruct}}
        list := make(tlv.StructArray, 0, len(s.{{.Name}}))
        for _, v := range s.{{.Name}} {
            list = append(list, v.Encode())
        }
        st[tlv.ContextTag({{.Tag}})] = list
        {{else}}
        list := make({{GetArrayType .PrimitiveType}}, 0, len(s.{{.Name}}))
        for _, v := range s.{{.Name}} {
            list = append(list, {{CastToTarget .PrimitiveType}}(v))
        }
        st[tlv.ContextTag({{.Tag}})] = list
        {{end}}
    }{{else}}
        {{if .IsStruct}}st[tlv.ContextTag({{.Tag}})] = s.{{.Name}}.Encode()
        {{else}}st[tlv.ContextTag({{.Tag}})] = {{CastToTarget .PrimitiveType}}(s.{{.Name}}){{end}}
    {{end}}{{end}}
{{end}}	return st
}

func (s *{{.Name}}) Decode(val any) error {
	st, ok := val.(tlv.Struct)
	if !ok {
		return fmt.Errorf("expected tlv.Struct, got %T", val)
	}
{{range .Fields}}	if val, ok := st[tlv.ContextTag({{.Tag}})]; ok {
        {{if .IsList}}
            {{if .IsStruct}}
            if list, ok := val.(tlv.StructArray); ok {
                 for _, item := range list {
                    var newItem {{.BaseType}}
                    if err := newItem.Decode(item); err != nil { return err }
                    s.{{.Name}} = append(s.{{.Name}}, newItem)
                 }
            }
            {{else}}
            if arr, ok := val.({{GetArrayType .PrimitiveType}}); ok {
                 for _, item := range arr {
                     s.{{.Name}} = append(s.{{.Name}}, {{.BaseType}}(item))
                 }
            }
            {{end}}
        {{else}}
        {{if .IsStruct}}{{if .IsPointer}}s.{{.Name}} = &{{.BaseType}}{}
        if err := s.{{.Name}}.Decode(val); err != nil { return err }{{else}}if err := s.{{.Name}}.Decode(val); err != nil { return err }{{end}}
        {{else}}
            {{DecodePrimitive "val" .PrimitiveType .BaseType .IsPointer .Name}}
        {{end}}
        {{end}}
	}
{{end}}
    return nil
}
{{end}}
`
	funcMap := template.FuncMap{
		"GetWriteMethod": func(goType string) string {
			switch goType {
			case "bool":
				return "Bool"
			case "uint8":
				return "UInt"
			case "uint16":
				return "UInt"
			case "uint32":
				return "UInt"
			case "uint64":
				return "UInt"
			case "int8":
				return "Int"
			case "int16":
				return "Int"
			case "int32":
				return "Int"
			case "int64":
				return "Int"
			case "float32":
				return "Float32"
			case "float64":
				return "Float64"
			case "string":
				return "UTF8"
			case "[]byte":
				return "OctetString"
			default:
				return "UInt"
			}
		},
		"CastToTarget": func(goType string) string {
			switch goType {
			case "bool", "string", "[]byte", "float32", "float64":
				return ""
			case "int8", "int16", "int32", "int64":
				return "int64"
			default:
				return "uint64"
			}
		},
		"GetArrayType": func(goType string) string {
			switch goType {
			case "bool":
				return "tlv.BoolArray"
			case "string":
				return "tlv.StringArray"
			case "[]byte":
				return "tlv.OctetStringArray"
			case "float32":
				return "tlv.FloatArray"
			case "float64":
				return "tlv.DoubleArray"
			case "int8", "int16", "int32", "int64":
				return "tlv.IntArray"
			default:
				return "tlv.UintArray"
			}
		},
		"DecodePrimitive": func(varName, primType, baseType string, isPointer bool, fieldName string) string {
			var castType string
			var checkType string
			switch primType {
			case "bool":
				checkType = "bool"
			case "string":
				checkType = "string"
			case "[]byte":
				checkType = "[]byte"
			case "float32":
				checkType = "float32"
			case "float64":
				checkType = "float64"
			case "int8", "int16", "int32", "int64":
				checkType = "int64"
				castType = baseType
			default:
				checkType = "uint64"
				castType = baseType
			}

			res := fmt.Sprintf("if v, ok := %s.(%s); ok {\n", varName, checkType)
			if castType != "" {
				res += fmt.Sprintf("casted := %s(v)\n", castType)
				if isPointer {
					res += fmt.Sprintf("s.%s = &casted\n", fieldName)
				} else {
					res += fmt.Sprintf("s.%s = casted\n", fieldName)
				}
			} else {
				if isPointer {
					res += fmt.Sprintf("s.%s = &v\n", fieldName)
				} else {
					res += fmt.Sprintf("s.%s = v\n", fieldName)
				}
			}
			res += "}"
			return res
		},
	}

	t := template.Must(template.New("structs").Funcs(funcMap).Parse(tmpl))

	enumNames := make(map[string]bool)
	for _, e := range enums {
		enumNames[e.Name] = true
	}

	var aliases []AliasDef
	for k, v := range Config.TypeAliases {
		if !enumNames[k] {
			aliases = append(aliases, AliasDef{Name: k, Base: v})
		}
	}
	sort.Slice(aliases, func(i, j int) bool { return aliases[i].Name < aliases[j].Name })

	f, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = t.Execute(f, GenData{Aliases: aliases, Structs: structs, Enums: enums})
	if err != nil {
		panic(err)
	}
}
