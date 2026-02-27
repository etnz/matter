package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path"
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
	// TypeMapping maps matter defined types into their Go representation.
	TypeMapping map[string]GoType

	TypeAliases  map[GoType]GoType
	KnownStructs map[GoType]bool
}

var Config = generatorConfig{
	TypeMapping: map[string]GoType{
		"octstr": gobyteSlice,
		"uint8":  gouint8,
		"uint16": gouint16,
		"uint32": gouint32,
		"uint64": gouint64,
		"int8":   goint8,
		"int16":  goint16,
		"int32":  goint32,
		"int64":  goint64,
		"string": gostring,
		"bool":   gobool,
		"float":  gofloat32,
		"double": gofloat64,

		"subject-id":               {Pkg: "dm", Name: "SubjectID"},
		"message-id":               {Pkg: "dm", Name: "MessageID"},
		"node-id":                  {Pkg: "dm", Name: "NodeID"},
		"fabric-id":                {Pkg: "dm", Name: "FabricID"},
		"event-no":                 {Pkg: "dm", Name: "EventNumber"},
		"cluster-id":               {Pkg: "dm", Name: "ClusterID"},
		"attrib-id":                {Pkg: "dm", Name: "AttributeID"},
		"attribute-id":             {Pkg: "dm", Name: "AttributeID"},
		"command-id":               {Pkg: "dm", Name: "CommandID"},
		"event-id":                 {Pkg: "dm", Name: "EventID"},
		"devtype-id":               {Pkg: "dm", Name: "DeviceTypeID"},
		"data-ver":                 {Pkg: "dm", Name: "DataVersion"},
		"endpoint-no":              {Pkg: "dm", Name: "EndpointID"},
		"group-id":                 {Pkg: "dm", Name: "GroupID"},
		"vendor-id":                {Pkg: "dm", Name: "VendorID"},
		"entry-idx":                {Pkg: "dm", Name: "EntryIndex"},
		"fabric-idx":               {Pkg: "dm", Name: "FabricIndex"},
		"action-id":                {Pkg: "dm", Name: "ActionID"},
		"epoch-s":                  {Pkg: "dm", Name: "EpochS"},
		"epoch-us":                 {Pkg: "dm", Name: "EpochUS"},
		"systime-ms":               {Pkg: "dm", Name: "SystemTimeMS"},
		"elapsed-s":                {Pkg: "dm", Name: "ElapsedS"},
		"power-mW":                 {Pkg: "dm", Name: "PowerMW"},
		"energy-mWh":               {Pkg: "dm", Name: "EnergyMWh"},
		"temperature":              {Pkg: "dm", Name: "Temperature"},
		"percent":                  {Pkg: "dm", Name: "Percent"},
		"percent100ths":            {Pkg: "dm", Name: "Percent100ths"},
		"hwadr":                    {Pkg: "dm", Name: "HardwareAddress"},
		"posix-ms":                 {Pkg: "dm", Name: "PosixMS"},
		"systime-us":               {Pkg: "dm", Name: "SystemTimeUS"},
		"utc":                      {Pkg: "dm", Name: "UTC"},
		"amperage-mA":              {Pkg: "dm", Name: "AmperageMA"},
		"voltage-mW":               {Pkg: "dm", Name: "VoltageMW"},
		"field-id":                 {Pkg: "dm", Name: "FieldID"},
		"trans-id":                 {Pkg: "dm", Name: "TransactionID"},
		"enum8":                    {Pkg: "dm", Name: "Enum8"},
		"enum16":                   {Pkg: "dm", Name: "Enum16"},
		"status":                   {Pkg: "dm", Name: "Status"},
		"priority":                 {Pkg: "dm", Name: "Priority"},
		"ipadr":                    {Pkg: "dm", Name: "IPAddress"},
		"ipv4adr":                  {Pkg: "dm", Name: "IPv4Address"},
		"ipv6adr":                  {Pkg: "dm", Name: "IPv6Address"},
		"ipv6pre":                  {Pkg: "dm", Name: "IPv6Prefix"},
		"namespace":                {Pkg: "dm", Name: "Namespace"},
		"tag":                      {Pkg: "dm", Name: "Tag"},
		"MeasurementTypeEnum":      {Pkg: "dm", Name: "MeasurementTypeEnum"},
		"locationdesc":             {Pkg: "dm", Name: "LocationDescriptor"},
		"LocationDescriptorStruct": {Pkg: "dm", Name: "LocationDescriptor"},
	},
	TypeAliases: map[GoType]GoType{
		{Pkg: "dm", Name: "SubjectID"}:           gouint64,
		{Pkg: "dm", Name: "MessageID"}:           gobyteSlice,
		{Pkg: "dm", Name: "NodeID"}:              gouint64,
		{Pkg: "dm", Name: "FabricID"}:            gouint64,
		{Pkg: "dm", Name: "EventNumber"}:         gouint64,
		{Pkg: "dm", Name: "ClusterID"}:           gouint32,
		{Pkg: "dm", Name: "AttributeID"}:         gouint32,
		{Pkg: "dm", Name: "CommandID"}:           gouint32,
		{Pkg: "dm", Name: "EventID"}:             gouint32,
		{Pkg: "dm", Name: "DeviceTypeID"}:        gouint32,
		{Pkg: "dm", Name: "DataVersion"}:         gouint32,
		{Pkg: "dm", Name: "EndpointID"}:          gouint16,
		{Pkg: "dm", Name: "GroupID"}:             gouint16,
		{Pkg: "dm", Name: "VendorID"}:            gouint16,
		{Pkg: "dm", Name: "EntryIndex"}:          gouint16,
		{Pkg: "dm", Name: "FabricIndex"}:         gouint8,
		{Pkg: "dm", Name: "ActionID"}:            gouint8,
		{Pkg: "dm", Name: "EpochS"}:              gouint32,
		{Pkg: "dm", Name: "EpochUS"}:             gouint64,
		{Pkg: "dm", Name: "SystemTimeMS"}:        gouint64,
		{Pkg: "dm", Name: "ElapsedS"}:            gouint32,
		{Pkg: "dm", Name: "PowerMW"}:             goint64,
		{Pkg: "dm", Name: "EnergyMWh"}:           goint64,
		{Pkg: "dm", Name: "Temperature"}:         goint16,
		{Pkg: "dm", Name: "Percent"}:             gouint8,
		{Pkg: "dm", Name: "Percent100ths"}:       gouint16,
		{Pkg: "dm", Name: "HardwareAddress"}:     gobyteSlice,
		{Pkg: "dm", Name: "PosixMS"}:             gouint64,
		{Pkg: "dm", Name: "SystemTimeUS"}:        gouint64,
		{Pkg: "dm", Name: "UTC"}:                 gouint32,
		{Pkg: "dm", Name: "AmperageMA"}:          goint64,
		{Pkg: "dm", Name: "VoltageMW"}:           goint64,
		{Pkg: "dm", Name: "FieldID"}:             gouint32,
		{Pkg: "dm", Name: "TransactionID"}:       gouint32,
		{Pkg: "dm", Name: "Enum8"}:               gouint8,
		{Pkg: "dm", Name: "Enum16"}:              gouint16,
		{Pkg: "dm", Name: "Status"}:              gouint8,
		{Pkg: "dm", Name: "Priority"}:            gouint8,
		{Pkg: "dm", Name: "IPAddress"}:           gobyteSlice,
		{Pkg: "dm", Name: "IPv4Address"}:         gobyteSlice,
		{Pkg: "dm", Name: "IPv6Address"}:         gobyteSlice,
		{Pkg: "dm", Name: "IPv6Prefix"}:          gobyteSlice,
		{Pkg: "dm", Name: "Namespace"}:           gouint8,
		{Pkg: "dm", Name: "Tag"}:                 gouint8,
		{Pkg: "dm", Name: "MeasurementTypeEnum"}: gouint16,
	},
	KnownStructs: map[GoType]bool{
		{Pkg: "dm", Name: "LocationDescriptor"}: true,
	},
}

func (c *generatorConfig) RenameType(cluster, name string) GoType {
	//
	pkg := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(cluster, " ", ""), "-", ""), "/", "")
	pkg = strings.ToLower(pkg)

	name = strings.TrimSuffix(name, "Struct")

	return GoType{
		Pkg:  pkg,
		Name: name,
	}
}

func (c *generatorConfig) RenameField(name string) string {
	return name
}

func (c *generatorConfig) RenameCluster(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", ""), "/", "")
}

func (c *generatorConfig) RenameEnumValue(enumName GoType, valueName string) string {
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
	XMLName        xml.Name           `xml:"cluster"`
	Name           string             `xml:"name,attr"`
	DataTypes      *DataTypes         `xml:"dataTypes"`
	Classification *ClassificationDef `xml:"classification"`
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
	Pkg     string
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
	Pkg     string
}

type EnumItem struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type BitmapDef struct {
	Name    string        `xml:"name,attr"`
	Items   []BitfieldDef `xml:"bitfield"`
	Cluster string
	Pkg     string
}

type BitfieldDef struct {
	Name string `xml:"name,attr"`
	Bit  int    `xml:"bit,attr"`
}

type NumberDef struct {
	Name    string `xml:"name,attr"`
	Type    string `xml:"type,attr"`
	Cluster string
	Pkg     string
}

type ClassificationDef struct {
	Hierarchy   string `xml:"hierarchy,attr"`
	BaseCluster string `xml:"baseCluster,attr"`
	Role        string `xml:"role,attr"`
	PicsCode    string `xml:"picsCode,attr"`
	Scope       string `xml:"scope,attr"`
}

// --- Go Generation Structures ---

type GoType struct {
	Pkg, Name string
	slice     bool
}

func (g GoType) String() string {
	if g.slice {
		return "[]" + g.Name
	}
	return g.Name
}
func (g GoType) Decl(pkg string) string {
	var decl string
	if g.Pkg == "" || g.Pkg == pkg {
		return g.String()
	}
	decl = g.Pkg + "." + g.Name

	if g.slice {
		decl = "[]" + decl
	}
	return decl
}

var (
	gobool      = GoType{Name: "bool"}
	gostring    = GoType{Name: "string"}
	gofloat32   = GoType{Name: "float32"}
	gofloat64   = GoType{Name: "float64"}
	gobyteSlice = GoType{Name: "byte", slice: true}
	goint8      = GoType{Name: "int8"}
	goint16     = GoType{Name: "int16"}
	goint32     = GoType{Name: "int32"}
	goint64     = GoType{Name: "int64"}
	gouint8     = GoType{Name: "uint8"}
	gouint16    = GoType{Name: "uint16"}
	gouint32    = GoType{Name: "uint32"}
	gouint64    = GoType{Name: "uint64"}
)

type GoStruct struct {
	Name   GoType
	Fields []GoField
}

type GoField struct {
	Name          string
	Type          GoType
	Tag           int
	IsPointer     bool
	IsList        bool
	IsStruct      bool
	BaseType      GoType
	PrimitiveType GoType
}

type GoEnum struct {
	Name     GoType
	BaseType GoType
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
	rootDir := os.Args[1]

	var rawStructs []StructDef
	var clusters map[string]ClusterRoot = make(map[string]ClusterRoot)
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
				s.Cluster = "dm"
				rawStructs = append(rawStructs, s)
			}
		}

		var eRoot EnumsRoot
		if xml.Unmarshal(data, &eRoot) == nil && len(eRoot.Enums) > 0 {
			for _, e := range eRoot.Enums {
				e.Cluster = "dm"
				rawEnums = append(rawEnums, e)
			}
		}

		var cRoot ClusterRoot
		if xml.Unmarshal(data, &cRoot) == nil && cRoot.DataTypes != nil {
			clusters[cRoot.Name] = cRoot

			// Reads a cluster definition.
			// Fill the 'Cluster' fields for every embedded struct of Enum or Bitmaps or Numbers, and then append them to the global list.
			for i := range cRoot.DataTypes.Structs {
				cRoot.DataTypes.Structs[i].Cluster = cRoot.Name
				cRoot.DataTypes.Structs[i].Pkg = cRoot.Classification.PicsCode
			}
			for i := range cRoot.DataTypes.Enums {
				cRoot.DataTypes.Enums[i].Cluster = cRoot.Name
				cRoot.DataTypes.Enums[i].Pkg = cRoot.Classification.PicsCode
			}
			for i := range cRoot.DataTypes.Bitmaps {
				cRoot.DataTypes.Bitmaps[i].Cluster = cRoot.Name
				cRoot.DataTypes.Bitmaps[i].Pkg = cRoot.Classification.PicsCode
			}
			for i := range cRoot.DataTypes.Numbers {
				cRoot.DataTypes.Numbers[i].Cluster = cRoot.Name
				cRoot.DataTypes.Numbers[i].Pkg = cRoot.Classification.PicsCode
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

	// every type (struct or enum etc.) in the definition is given an absolute "matter" name.
	// it is not a programming language so usually it is the cluster name + type name.

	// Pre-register structs to handle forward references and cluster scoping
	for _, s := range rawStructs {
		name := s.Cluster + s.Name
		goName := Config.RenameType(s.Pkg, s.Name)
		Config.TypeMapping[name] = goName // map the struct type to a go type
		Config.KnownStructs[goName] = true
	}

	for _, n := range rawNumbers {
		name := n.Cluster + n.Name
		goName := Config.RenameType(n.Pkg, n.Name)
		baseType := GoType{
			Pkg:  n.Cluster,
			Name: n.Type,
		}
		if mapped, ok := Config.TypeMapping[n.Type]; ok {
			baseType = mapped
		}
		Config.TypeMapping[name] = goName
		Config.TypeAliases[goName] = baseType
	}
	// GoNames are fully qualified names (package . type ) be careful.

	// Create the "Go" version of each matter type
	var enums []GoEnum
	for _, e := range rawEnums {
		enums = append(enums, processEnum(e))
	}
	for _, b := range rawBitmaps {
		enums = append(enums, processBitmap(b))
	}

	var structs []GoStruct
	for _, s := range rawStructs {
		gostruct := processStruct(s, clusters)
		if gostruct.Name.Name == "" {
			continue
		}
		structs = append(structs, gostruct)
	}

	generateGoCode(structs, enums)
}

func processEnum(e EnumDef) GoEnum {
	name := e.Cluster + e.Name
	goName := Config.RenameType(e.Pkg, e.Name)

	ge := GoEnum{
		Name: goName,
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
		ge.BaseType = gouint8
	} else if maxVal <= 65535 {
		ge.BaseType = gouint16
	} else {
		ge.BaseType = gouint32
	}

	// Register the enum in the type mapping so structs can use it
	Config.TypeMapping[name] = ge.Name
	// Register the alias so it is treated as a primitive type (not a struct)
	Config.TypeAliases[ge.Name] = ge.BaseType

	return ge
}

func processBitmap(b BitmapDef) GoEnum {
	name := b.Cluster + b.Name
	goName := Config.RenameType(b.Pkg, b.Name)
	ge := GoEnum{
		Name: goName,
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
		ge.BaseType = gouint8
	} else if maxBit < 16 {
		ge.BaseType = gouint16
	} else if maxBit < 32 {
		ge.BaseType = gouint32
	} else {
		ge.BaseType = gouint64
	}

	Config.TypeMapping[name] = ge.Name
	Config.TypeAliases[ge.Name] = ge.BaseType

	return ge
}

func processStruct(s StructDef, clusters map[string]ClusterRoot) GoStruct {
	// If the cluster is not a base cluster, resolve the parent one
	c := clusters[s.Cluster]
	if c.Classification != nil && c.Classification.BaseCluster != "" {
		base := c.Classification.BaseCluster + " Cluster" // OMG that's horrible.
		// look into the base cluster if there is a definition for this struct.
		if baseCluster, ok := clusters[base]; ok {
			for _, st := range baseCluster.DataTypes.Structs {
				if st.Name == s.Name {
					// 	In the Matter data model, a derived cluster does **not** change the structural definition of a base struct like `ModeOptionStruct`.
					//
					// When an application cluster (like Dishwasher Mode) inherits from a base cluster (like Mode Base), it reuses the exact same structural blueprint. The Field IDs, Names, and Base Data Types of the struct remain strictly identical.
					//
					// Here is exactly how the relationship works according to the specification:
					//
					// **1. What the derived cluster CAN change (Overrides)**
					// While the data types cannot change, a derived cluster is allowed to override the **conformance, constraints, or access qualities** of the inherited elements. For example, a derived cluster can:
					// *   Make an optional base field mandatory.
					// *   Remove or disallow a field that was optional in the base specification.
					// *   Apply stricter constraints, such as limiting the maximum length of a string or restricting the allowed range of an integer.
					//
					// **2. How new fields are added**
					// If a derived appliance cluster needs a completely new field in `ModeOptionStruct` that does not currently exist, it is not supposed to blindly inject it into its own derived version of the struct. The specification explicitly states that new features or elements SHOULD be added to the **base cluster specification** as optional elements. This ensures that the struct maintains a single, globally consistent namespace and definition across all possible derived modes.
					//
					// *(Note: The only exception to this is if a manufacturer wants to add custom, non-standard fields, in which case they use Manufacturer Specific (MS) extensions with their own Vendor ID, rather than altering the standard struct.)*
					//
					// **Why this caused your XML errors:**
					// This architectural rule perfectly explains the missing types in your XML files. Because the fundamental shape and data types of `ModeOptionStruct` are exclusively "owned" by the Mode Base cluster, the XML files for the derived clusters (Dishwasher, Oven, Laundry, etc.) do not redefine them. Your XML parser or code generator must be programmed to look up the inheritance tree to the base cluster's schema to successfully resolve the underlying data types for `Label`, `Mode`, and `ModeTags`.

					// We do not handle those changes, yet. so we can safely ignore that struct.

					// fmt.Printf("%s.%s extends %s.%s\n", s.Cluster, s.Name, base, st.Name)
					return GoStruct{} // returns an empty GoStruct
				}
			}
		} else {
			fmt.Println("unknown cluster", base, clusters)
		}
	}

	goName := Config.RenameType(s.Pkg, s.Name)
	gs := GoStruct{
		Name: goName,
	}

	for _, f := range s.Fields {
		if f.DeprecateConform != nil {
			continue
		}
		if f.Type == "" {
			// cluster Electrical Power Measurement Cluster struct MeasurementRangeStruct field MeasurementType has no type : should be MeasurementTypeEnum
			if s.Cluster == "Electrical Power Measurement Cluster" && f.Name == "MeasurementType" {
				f.Type = "MeasurementTypeEnum"
			} else if s.Cluster == "Joint Fabric Datastore Cluster" && f.Name == "FailureCode" {
				// cluster Joint Fabric Datastore Cluster struct DatastoreStatusEntryStruct field FailureCode has no type: should be status
				f.Type = "status"
			} else {
				fmt.Printf("cluster %s struct %s field %s has no type\n", s.Cluster, s.Name, f.Name)
			}
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
			goType = Config.RenameType(s.Pkg, xmlType)
			gf.IsStruct = true
			gf.PrimitiveType = goType

			if s.Cluster == "Channel Cluster" && xmlType == "AdditionalInfoStruct" {
				// exception: AdditionalInfoStruct from ChannelCluster is defined elsewhere
				fmt.Println("exception: AdditionalInfoStruct from Channel Cluster is defined in Content Launcher Cluster")
				goType = Config.RenameType("CONTENTLAUNCHER", "AdditionalInfoStruct")
				gf.PrimitiveType = goType
			}
			// Content Launcher Cluster CharacteristicEnum is defined Media Playback Cluster
			if s.Cluster == "Content Launcher Cluster" && xmlType == "CharacteristicEnum" {
				// exception: AdditionalInfoStruct from ChannelCluster is defined elsewhere
				fmt.Println("exception: CharacteristicEnum from Content Launcher Cluster is defined in Media Playback Cluster")
				goType = Config.RenameType("MEDIAPLAYBACK", "CharacteristicEnum")
				gf.IsStruct = false
				gf.PrimitiveType = gouint8
			}
			// if xmlType == "LocationDescriptorStruct" {
			// 	fmt.Println("handling LocationDescriptor")
			// 	goType = GoType{Pkg: "dm", Name: "LocationDescriptor"}
			// 	gf.PrimitiveType = goType

			// }
			// if xmlType == "MeasurementTypeEnum" {
			// 	fmt.Println("handling MeasurementType")
			// 	goType = GoType{Pkg: "dm", Name: "MeasurementType"}
			// 	gf.PrimitiveType = goType

			// }

		}
		gf.BaseType = goType

		if Config.KnownStructs[goType] {
			gf.IsStruct = true
		}

		gf.Type = goType
		if gf.IsList {
			gf.Type.slice = true
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
	Pkg     string // the package name
	Aliases []AliasDef
	Structs []GoStruct
	Enums   []GoEnum
}

type AliasDef struct {
	Name GoType
	Base GoType
}

func generateGoCode(structs []GoStruct, enums []GoEnum) {
	tmpl := `// Code generated by data_gen.go. DO NOT EDIT.
{{$pkg:= .Pkg}}
package {{.Pkg}}

import (
	"fmt"

	"github.com/etnz/matter/tlv"
	"github.com/etnz/matter/dm"
	{{range $k, $v:= Imports .Structs}}
	{{$k}}
	{{end}}
)

var _ = dm.SubjectID(0)
var _ = tlv.Struct{}
var _ = fmt.Sprint()


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
{{range .Fields}}	{{.Name}} {{if .IsPointer}}*{{end}}{{.Type.Decl $pkg}} // Tag {{.Tag}}
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
                    var newItem {{.BaseType.Decl $pkg}}
                    if err := newItem.Decode(item); err != nil { return err }
                    s.{{.Name}} = append(s.{{.Name}}, newItem)
                 }
            }
            {{else}}
            if arr, ok := val.({{GetArrayType .PrimitiveType}}); ok {
                 for _, item := range arr {
                     s.{{.Name}} = append(s.{{.Name}}, {{.BaseType.Decl $pkg}}(item))
                 }
            }
            {{end}}
        {{else}}
        {{if .IsStruct}}{{if .IsPointer}}s.{{.Name}} = &{{.BaseType.Decl $pkg}}{}
        if err := s.{{.Name}}.Decode(val); err != nil { return err }{{else}}if err := s.{{.Name}}.Decode(val); err != nil { return err }{{end}}
        {{else}}
            {{DecodePrimitive $pkg "val" .PrimitiveType .BaseType .IsPointer .Name}}
        {{end}}
        {{end}}
	}
{{end}}
    return nil
}
{{end}}
`
	funcMap := template.FuncMap{
		"CastToTarget": func(goType GoType) string {
			switch goType {
			case gobool, gostring, gofloat32, gofloat64:
				return ""
			case gobyteSlice:
				return "[]byte"
			case goint8, goint16, goint32, goint64:
				return "int64"
			case gouint8, gouint16, gouint32, gouint64:
				return "uint64"
			default:
				fmt.Println("CastToTarget", goType.Pkg, goType.Name, "unknown")
				return "unknown"
			}
		},
		"GetArrayType": func(goType GoType) string {
			switch goType {
			case gobool:
				return "tlv.BoolArray"
			case gostring:
				return "tlv.StringArray"
			case gobyteSlice:
				return "tlv.OctetStringArray"
			case gofloat32:
				return "tlv.Float32Array"
			case gofloat64:
				return "tlv.DoubleArray"
			case goint8, goint16, goint32, goint64:
				return "tlv.IntArray"
			default:
				return "tlv.UintArray"
			}
		},
		"Imports": func(structs []GoStruct) map[string]struct{} {
			imports := make(map[string]struct{})
			for _, s := range structs {
				for _, f := range s.Fields {
					if f.Type.Pkg != s.Name.Pkg && f.Type.Pkg != "" && f.Type.Pkg != "dm" {
						imp := "github.com/etnz/matter/dm/" + f.Type.Pkg
						imports[strconv.Quote(imp)] = struct{}{}
					}
				}
			}
			return imports

		},
		"DecodePrimitive": func(pkg, varName string, primType, baseType GoType, isPointer bool, fieldName string) string {
			var castType GoType
			var checkType string
			switch primType {
			case gobool, gostring, gofloat32, gofloat64:
				checkType = primType.Name
			case gobyteSlice:
				checkType = "[]byte"
			case goint8, goint16, goint32, goint64:
				checkType = "int64"
				castType = baseType
			default:
				checkType = "uint64"
				castType = baseType
			}

			res := fmt.Sprintf("if v, ok := %s.(%s); ok {\n", varName, checkType)
			if (castType != GoType{}) {
				res += fmt.Sprintf("casted := %s(v)\n", castType.Decl(pkg))
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

	// Creates a set of all enum names
	enumNames := make(map[GoType]struct{})
	for _, e := range enums {
		enumNames[e.Name] = struct{}{}
	}

	// and build an alias definition for type that are not part of the enuns
	var aliases []AliasDef
	for k, v := range Config.TypeAliases {
		if _, ok := enumNames[k]; !ok {
			aliases = append(aliases, AliasDef{Name: k, Base: v})
		}
	}
	sort.Slice(aliases, func(i, j int) bool { return aliases[i].Name.Name < aliases[j].Name.Name })

	// generation: organize things per packages, thre is one file per package.
	pkgs := make(map[string]*GenData)

	for _, s := range structs {
		if _, ok := pkgs[s.Name.Pkg]; !ok {
			pkgs[s.Name.Pkg] = &GenData{Pkg: s.Name.Pkg}
		}
		pkgs[s.Name.Pkg].Structs = append(pkgs[s.Name.Pkg].Structs, s)

	}

	for _, s := range enums {
		if _, ok := pkgs[s.Name.Pkg]; !ok {
			pkgs[s.Name.Pkg] = &GenData{Pkg: s.Name.Pkg}
		}
		pkgs[s.Name.Pkg].Enums = append(pkgs[s.Name.Pkg].Enums, s)
	}

	//GenData{Aliases: aliases, Structs: structs, Enums: enums}
	// TODO: also add the aliases and enums

	for name, g := range pkgs {
		tgt := path.Join("dm", name, "data.go")
		os.MkdirAll(path.Dir(tgt), 0755)

		f, err := os.Create(tgt)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		err = t.Execute(f, g)
		if err != nil {
			panic(err)
		}
	}
}
