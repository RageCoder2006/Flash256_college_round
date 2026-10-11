package api

import (
	"encoding/json"
	"reflect"
)

var marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

// nonNull returns a copy of v where every nil slice and map is empty, so the JSON has [] and {} instead of null.
// The dashboard types those fields as arrays and objects and would crash on null.
func nonNull(v any) any {
	if v == nil {
		return nil
	}
	return denull(reflect.ValueOf(v)).Interface()
}

func denull(v reflect.Value) reflect.Value {
	t := v.Type()
	if t.Implements(marshalerType) || reflect.PointerTo(t).Implements(marshalerType) {
		return v
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		n := reflect.New(t).Elem()
		n.Set(denull(v.Elem()))
		return n
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		p := reflect.New(t.Elem())
		p.Elem().Set(denull(v.Elem()))
		return p
	case reflect.Struct:
		n := reflect.New(t).Elem()
		n.Set(v)
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() {
				n.Field(i).Set(denull(v.Field(i)))
			}
		}
		return n
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return v
		}
		n := reflect.MakeSlice(t, v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			n.Index(i).Set(denull(v.Index(i)))
		}
		return n
	case reflect.Map:
		n := reflect.MakeMapWithSize(t, v.Len())
		for _, k := range v.MapKeys() {
			n.SetMapIndex(k, denull(v.MapIndex(k)))
		}
		return n
	}
	return v
}
